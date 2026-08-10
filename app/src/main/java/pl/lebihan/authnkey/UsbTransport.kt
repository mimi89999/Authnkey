package pl.lebihan.authnkey

import android.hardware.usb.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.ByteOrder
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

    sealed class TransportError(message: String) : Exception(message) {
        class UnsupportedPacketSize(size: Int) :
            TransportError("Unsupported HID packet size: $size bytes")

        class ProtocolViolation(detail: String) :
            TransportError("CTAPHID protocol violation: $detail")

        class TransferFailed(detail: String) :
            TransportError("USB transfer failed: $detail")

        class ResponseTimeout :
            TransportError("Timed out waiting for a response from the security key")

        class MessageTooLarge(size: Int, limit: Int) :
            TransportError("Message of $size bytes exceeds the CTAPHID limit of $limit bytes")

        class HidError(code: Int) : TransportError(
            "CTAPHID error: ${label(code)} (0x${code.toString(16).padStart(2, '0')})"
        ) {
            private companion object {
                fun label(code: Int) = when (code) {
                    0x01 -> "INVALID_CMD"
                    0x02 -> "INVALID_PAR"
                    0x03 -> "INVALID_LEN"
                    0x04 -> "INVALID_SEQ"
                    0x05 -> "MSG_TIMEOUT"
                    0x06 -> "CHANNEL_BUSY"
                    0x0A -> "LOCK_REQUIRED"
                    0x0B -> "INVALID_CHANNEL"
                    0x7F -> "OTHER"
                    else -> "UNKNOWN"
                }
            }
        }
    }

    override val transportType = TransportType.USB

    private var channelId: Int = CID_BROADCAST
    @Volatile
    private var _isConnected = true

    override val isConnected: Boolean
        get() = _isConnected

    private val inPacketSize = inEndpoint.maxPacketSize
    private val outPacketSize = outEndpoint.maxPacketSize

    private val outMaxMessageSize =
        minOf(outPacketSize - 7 + 128 * (outPacketSize - 5), 0xFFFF)

    /**
     * Initialize CTAPHID channel, claiming a channel id from the broadcast channel.
     */
    private suspend fun init() = withContext(Dispatchers.IO) {
        val nonce = ByteArray(8).also { Random.nextBytes(it) }
        val response = sendRaw(CID_BROADCAST, CMD_INIT, nonce)

        if (response.size < 17) {
            throw TransportError.ProtocolViolation("INIT response is ${response.size} bytes")
        }

        val receivedNonce = response.sliceArray(0..7)
        if (!receivedNonce.contentEquals(nonce)) {
            throw TransportError.ProtocolViolation("Nonce mismatch")
        }

        // Extract channel ID (bytes 8-11, big endian)
        channelId = ByteBuffer.wrap(response, 8, 4).order(ByteOrder.BIG_ENDIAN).int
    }

    override fun reclaimConnection() {
        if (!_isConnected || !connection.claimInterface(hidInterface, false)) {
            throw AuthnkeyError.NotConnected()
        }
        auxiliaryInterfaces.forEach { connection.claimInterface(it, true) }
    }

    override suspend fun sendCtapCommand(command: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        // CTAPHID_CBOR command
        sendRaw(channelId, CMD_CBOR, command)
    }

    private fun sendRaw(cid: Int, cmd: Int, data: ByteArray): ByteArray {
        if (data.size > outMaxMessageSize) {
            throw TransportError.MessageTooLarge(data.size, outMaxMessageSize)
        }

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

        // Data (up to packetSize - 7 bytes in init packet)
        val initDataLen = minOf(data.size, outPacketSize - 7)
        System.arraycopy(data, 0, initPacket, 7, initDataLen)
        offset = initDataLen

        // Send init packet
        sendPacket(initPacket)

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

            sendPacket(contPacket)
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
            // Check if we've exceeded max wait time
            if (System.currentTimeMillis() - startTime > maxWaitTime) {
                throw TransportError.ResponseTimeout()
            }

            // Timeout on this read, but keep trying if within max wait time
            val packet = receivePacket() ?: continue
            val received = packet.size

            if (received < 5) {
                throw TransportError.ProtocolViolation("Received packet of $received bytes")
            }

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

            if (cmdOrSeq == (CMD_ERROR or 0x80)) {
                if (received < 8) {
                    throw TransportError.ProtocolViolation("ERROR packet carries no error code")
                }
                throw TransportError.HidError(packet[7].toInt() and 0xFF)
            }

            if (isFirst) {
                // Init packet
                if ((cmdOrSeq and 0x80) == 0) {
                    throw TransportError.ProtocolViolation(
                        "Continuation packet received before initialization packet"
                    )
                }

                if (received < 7) {
                    throw TransportError.ProtocolViolation(
                        "Received initialization packet of $received bytes"
                    )
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
                if ((cmdOrSeq and 0x80) != 0) {
                    throw TransportError.ProtocolViolation("Unexpected initialization packet")
                }

                if (cmdOrSeq != expectedSeq) {
                    throw TransportError.ProtocolViolation(
                        "Out of order continuation packet: Got seq $cmdOrSeq, expected $expectedSeq"
                    )
                }

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

    /**
     * Write a single HID packet to the out endpoint. Partial writes are not
     * supported by CTAPHID, so anything short of the full packet is an error.
     */
    private fun sendPacket(packet: ByteArray) {
        if (!_isConnected) throw AuthnkeyError.NotConnected()

        val sent = connection.bulkTransfer(outEndpoint, packet, packet.size, TIMEOUT_MS)
        if (sent < 0) {
            throw TransportError.TransferFailed("Failed to write packet to the out endpoint")
        }
        if (sent != packet.size) {
            throw TransportError.TransferFailed("Wrote $sent of ${packet.size} bytes")
        }
    }

    /**
     * Read a single HID packet from the in endpoint, trimmed to its actual
     * length, or null if the read failed or nothing arrived within [TIMEOUT_MS].
     */
    private fun receivePacket(): ByteArray? {
        if (!_isConnected) throw AuthnkeyError.NotConnected()

        val packet = ByteArray(inPacketSize)
        val received = connection.bulkTransfer(inEndpoint, packet, packet.size, TIMEOUT_MS)
        if (received <= 0) return null
        return packet.copyOf(received)
    }

    override fun close() {
        _isConnected = false
        try {
            auxiliaryInterfaces.forEach {
                try { connection.releaseInterface(it) } catch (_: Exception) {}
            }
            connection.releaseInterface(hidInterface)
            connection.close()
        } catch (e: Exception) {
            // Ignore
        }
    }

    companion object {
        private const val CID_BROADCAST = 0xFFFFFFFF.toInt()
        private const val CMD_INIT = 0x06
        private const val CMD_CBOR = 0x10
        private const val CMD_KEEPALIVE = 0x3B
        private const val CMD_ERROR = 0x3F
        private const val TIMEOUT_MS = 5000

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

            for (ep in listOf(inEp, outEp)) {
                if (ep.maxPacketSize < 8) {
                    throw TransportError.UnsupportedPacketSize(ep.maxPacketSize)
                }
            }

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

            try {
                transport.init()
            } catch (e: Exception) {
                transport.close()
                throw e
            }
            return transport
        }
    }
}
