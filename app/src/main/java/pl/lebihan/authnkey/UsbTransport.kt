package pl.lebihan.authnkey

import android.hardware.usb.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.random.Random

/**
 * FIDO transport over USB HID using CTAPHID protocol
 */
class UsbTransport private constructor(
    val deviceId: Int,
    private val connection: UsbDeviceConnection,
    private val hidInterface: UsbInterface,
    private val inEndpoint: UsbEndpoint,
    private val outEndpoint: UsbEndpoint,
    private val auxiliaryInterfaces: List<UsbInterface>
) : FidoTransport {

    override val transportType = TransportType.USB

    private var channelId: Int = CID_BROADCAST
    @Volatile private var closed = false
    private val transferLock = ReentrantLock()

    override val isConnected: Boolean
        get() = !closed

    private val inPacketSize = inEndpoint.maxPacketSize.coerceAtLeast(64)
    private val outPacketSize = outEndpoint.maxPacketSize.coerceAtLeast(64)

    private val inRequest = UsbRequest().apply { initialize(connection, inEndpoint) }
    private val outRequest = UsbRequest().apply { initialize(connection, outEndpoint) }

    /**
     * Transfers a single HID report, sending or receiving depending on the direction
     * of this request's endpoint. [buffer] holds the report to send, or is filled
     * with the one received.
     *
     * Returns the number of bytes transferred, or -1 if nothing arrived within
     * [timeoutMs].
     */
    private fun UsbRequest.transfer(buffer: ByteBuffer, timeoutMs: Long): Int = transferLock.withLock {
        if (closed) return -1
        if (!queue(buffer)) return -1
        val completed = try {
            connection.requestWait(timeoutMs)
        } catch (e: TimeoutException) {
            // The request stays queued after a timeout, so cancel and reap it
            cancel()
            try { connection.requestWait(CANCEL_TIMEOUT_MS) } catch (_: Exception) {}
            null
        }
        return if (completed === this) buffer.position() else -1
    }

    /**
     * Initialize CTAPHID channel
     */
    private suspend fun init(): Boolean = withContext(Dispatchers.IO) {
        try {
            // Send INIT command to get a channel
            val nonce = ByteArray(8).also { Random.nextBytes(it) }
            val response = sendRaw(CID_BROADCAST, CMD_INIT, nonce)

            if (response.size >= 17) {
                // Verify nonce
                val receivedNonce = response.sliceArray(0..7)
                if (!receivedNonce.contentEquals(nonce)) {
                    throw Exception("Nonce mismatch")
                }

                // Extract channel ID (bytes 8-11, big endian)
                channelId = ByteBuffer.wrap(response, 8, 4).order(ByteOrder.BIG_ENDIAN).int
                true
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    override fun reclaimConnection() {
        if (closed) throw AuthnkeyError.NotConnected()
        if (!transferLock.tryLock()) return
        try {
            if (closed || !connection.claimInterface(hidInterface, false)) {
                throw AuthnkeyError.NotConnected()
            }
            auxiliaryInterfaces.forEach { connection.claimInterface(it, true) }
        } finally {
            transferLock.unlock()
        }
    }

    override suspend fun sendCtapCommand(command: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        // CTAPHID_CBOR command
        sendRaw(channelId, CMD_CBOR, command)
    }

    private fun sendRaw(cid: Int, cmd: Int, data: ByteArray): ByteArray {
        if (closed) throw AuthnkeyError.NotConnected()

        // Build and send initialization packet
        val initPacket = ByteArray(outPacketSize)
        var offset = 0

        // Channel ID (4 bytes, big endian)
        initPacket[0] = (cid shr 24).toByte()
        initPacket[1] = (cid shr 16).toByte()
        initPacket[2] = (cid shr 8).toByte()
        initPacket[3] = cid.toByte()

        // Command (1 byte, with bit 7 set for init packet)
        initPacket[4] = (cmd or 0x80).toByte()

        // Length (2 bytes, big endian)
        initPacket[5] = (data.size shr 8).toByte()
        initPacket[6] = (data.size and 0xFF).toByte()

        // Data (up to outPacketSize - 7 bytes in init packet)
        val initDataLen = minOf(data.size, outPacketSize - 7)
        System.arraycopy(data, 0, initPacket, 7, initDataLen)
        offset = initDataLen

        // Send init packet
        val sent = outRequest.transfer(ByteBuffer.wrap(initPacket), TIMEOUT_MS)
        if (sent < 0) throw Exception("Failed to send init packet")

        // Send continuation packets if needed
        var seq = 0
        while (offset < data.size) {
            val contPacket = ByteArray(outPacketSize)

            // Channel ID
            contPacket[0] = (cid shr 24).toByte()
            contPacket[1] = (cid shr 16).toByte()
            contPacket[2] = (cid shr 8).toByte()
            contPacket[3] = cid.toByte()

            // Sequence number (without bit 7)
            contPacket[4] = (seq and 0x7F).toByte()
            seq++

            // Data
            val contDataLen = minOf(data.size - offset, outPacketSize - 5)
            System.arraycopy(data, offset, contPacket, 5, contDataLen)
            offset += contDataLen

            val contSent = outRequest.transfer(ByteBuffer.wrap(contPacket), TIMEOUT_MS)
            if (contSent < 0) throw Exception("Failed to send continuation packet")
        }

        // Receive response
        return receiveResponse(cid)
    }

    private fun receiveResponse(expectedCid: Int): ByteArray {
        val responseData = mutableListOf<Byte>()
        var expectedLen = 0
        var receivedLen = 0
        var expectedSeq = 0
        var isFirst = true

        // Use longer timeout for operations that need user presence
        val startTime = System.currentTimeMillis()
        val maxWaitTime = 30000L // 30 seconds for user to touch the key

        while (true) {
            if (closed) throw AuthnkeyError.NotConnected()

            // Check if we've exceeded max wait time
            if (System.currentTimeMillis() - startTime > maxWaitTime) {
                throw Exception("Timeout waiting for response")
            }

            val packet = ByteArray(inPacketSize)
            val received = inRequest.transfer(ByteBuffer.wrap(packet), TIMEOUT_MS)

            if (received < 0) {
                // Timeout on this read, but keep trying if within max wait time
                continue
            }
            if (received < 5) continue

            // Parse channel ID
            val recvCid = ByteBuffer.wrap(packet, 0, 4).order(ByteOrder.BIG_ENDIAN).int
            if (recvCid != expectedCid) continue

            val cmdOrSeq = packet[4].toInt() and 0xFF

            // Handle KEEPALIVE messages (0x3B | 0x80 = 0xBB)
            if (cmdOrSeq == (CMD_KEEPALIVE or 0x80)) {
                // Keepalive status is in the data
                // 0x01 = processing, 0x02 = user presence needed
                // Just continue waiting
                continue
            }

            if (isFirst) {
                // Init packet
                if ((cmdOrSeq and 0x80) == 0) continue

                // Check for error
                if (cmdOrSeq == (CMD_ERROR or 0x80)) {
                    val errorCode = if (received > 7) packet[7] else 0
                    throw Exception("CTAPHID error: 0x${String.format("%02X", errorCode)}")
                }

                expectedLen = ((packet[5].toInt() and 0xFF) shl 8) or (packet[6].toInt() and 0xFF)
                val dataLen = minOf(expectedLen, received - 7)

                for (i in 0 until dataLen) {
                    responseData.add(packet[7 + i])
                }
                receivedLen = dataLen
                isFirst = false
            } else {
                // Continuation packet
                if ((cmdOrSeq and 0x80) != 0) continue
                if (cmdOrSeq != expectedSeq) continue

                expectedSeq++
                val dataLen = minOf(expectedLen - receivedLen, received - 5)

                for (i in 0 until dataLen) {
                    responseData.add(packet[5 + i])
                }
                receivedLen += dataLen
            }

            if (receivedLen >= expectedLen) {
                break
            }
        }

        return responseData.toByteArray()
    }

    override fun close() {
        if (closed) return
        closed = true

        // Break any in-flight wait so the transfer lock frees up promptly
        try { inRequest.cancel() } catch (_: Exception) {}
        try { outRequest.cancel() } catch (_: Exception) {}

        transferLock.withLock {
            try {
                inRequest.close()
                outRequest.close()
                auxiliaryInterfaces.forEach {
                    try { connection.releaseInterface(it) } catch (_: Exception) {}
                }
                connection.releaseInterface(hidInterface)
                connection.close()
            } catch (e: Exception) {
                // Ignore
            }
        }
    }

    companion object {
        private const val CID_BROADCAST = 0xFFFFFFFF.toInt()
        private const val CMD_INIT = 0x06
        private const val CMD_CBOR = 0x10
        private const val CMD_KEEPALIVE = 0x3B
        private const val CMD_ERROR = 0x3F
        private const val TIMEOUT_MS = 5000L
        private const val CANCEL_TIMEOUT_MS = 100L

        /**
         * Find FIDO HID interface on a USB device
         */
        fun findFidoInterface(device: UsbDevice): Pair<UsbInterface, Pair<UsbEndpoint, UsbEndpoint>>? {
            for (i in 0 until device.interfaceCount) {
                val intf = device.getInterface(i)

                // HID class = 3
                if (intf.interfaceClass != UsbConstants.USB_CLASS_HID) continue

                var inEp: UsbEndpoint? = null
                var outEp: UsbEndpoint? = null

                for (j in 0 until intf.endpointCount) {
                    val ep = intf.getEndpoint(j)
                    if (ep.type == UsbConstants.USB_ENDPOINT_XFER_INT) {
                        if (ep.direction == UsbConstants.USB_DIR_IN) {
                            inEp = ep
                        } else {
                            outEp = ep
                        }
                    }
                }

                if (inEp != null && outEp != null) {
                    return Pair(intf, Pair(inEp, outEp))
                }
            }
            return null
        }

        /**
         * Check if a device has a HID interface
         */
        fun isHidDevice(device: UsbDevice): Boolean {
            for (i in 0 until device.interfaceCount) {
                if (device.getInterface(i).interfaceClass == UsbConstants.USB_CLASS_HID) {
                    return true
                }
            }
            return false
        }

        /**
         * Check if a device might be a FIDO device based on known vendor IDs
         * or device name.
         *
         * Vendor list from https://github.com/Yubico/libfido2/blob/main/udev/fidodevs
         * with own additions.
         */
        fun isFidoDevice(device: UsbDevice): Boolean {
            val fidoVendors = setOf(
                0x0483,  // STMicroelectronics
                0x058b,  // Infineon
                0x06cb,  // Synaptics
                0x096e,  // Feitian
                0x1050,  // Yubico
                0x10c4,  // Silicon Labs
                0x1209,  // pid.codes
                0x18d1,  // Google
                0x1a44,  // VASCO
                0x1d50,  // OpenMoko
                0x1e0d,  // NEOWAVE
                0x1ea8,  // Excelsecu
                0x1fc9,  // NXP
                0x20a0,  // Clay Logic
                0x24dc,  // Aladdin
                0x2581,  // Plug-up
                0x2abe,  // Bluink
                0x2c97,  // Ledger
                0x2ccf,  // Hypersecu
                0x311f,  // eWBM
                0x32a3,  // GoTrustID
                0x349e,  // Token2
                0x4c4d,  // Unknown
                0x534c,  // SatoshiLabs
            )

            val nameMatch = device.productName?.let {
                it.contains("FIDO", ignoreCase = true) ||
                it.contains("U2F", ignoreCase = true) ||
                it.contains("Pico Key", ignoreCase = true)
            } ?: false

            return (fidoVendors.contains(device.vendorId) || nameMatch) && isHidDevice(device)
        }

        /**
         * Connect to a FIDO USB device.
         * Opens the HID interface and initializes the CTAPHID channel.
         */
        suspend fun connect(usbManager: UsbManager, device: UsbDevice): UsbTransport {
            val (hidInterface, endpoints) = findFidoInterface(device)
                ?: throw AuthnkeyError.ConnectionFailed()
            val (inEp, outEp) = endpoints

            val connection = usbManager.openDevice(device)
                ?: throw AuthnkeyError.ConnectionFailed()

            if (!connection.claimInterface(hidInterface, true)) {
                connection.close()
                throw AuthnkeyError.ConnectionFailed()
            }

            // Claim other HID interfaces (e.g. OTP keyboard) to detach the
            // kernel input driver and prevent soft keyboard suppression.
            val auxiliaryInterfaces = (0 until device.interfaceCount)
                .map { device.getInterface(it) }
                .filter { it != hidInterface && it.interfaceClass == UsbConstants.USB_CLASS_HID }

            auxiliaryInterfaces.forEach { connection.claimInterface(it, true) }

            val transport = UsbTransport(
                deviceId = device.deviceId,
                connection = connection,
                hidInterface = hidInterface,
                inEndpoint = inEp,
                outEndpoint = outEp,
                auxiliaryInterfaces = auxiliaryInterfaces,
            )

            if (!transport.init()) {
                transport.close()
                throw AuthnkeyError.ConnectionFailed()
            }
            return transport
        }
    }
}
