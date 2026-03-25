package pl.lebihan.authnkey

import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * FIDO transport over NFC using ISO 7816-4 APDUs
 */
class NfcTransport private constructor(private val isoDep: IsoDep) : FidoTransport {

    override val transportType = TransportType.NFC

    override val isConnected: Boolean
        get() = try {
            isoDep.isConnected
        } catch (e: SecurityException) {
            false
        }

    override fun reclaimConnection() {
        if (!isConnected) {
            throw AuthnkeyError.NotConnected()
        }
    }

    /**
     * Select the FIDO applet on the NFC device
     */
    private suspend fun selectFidoApplet(): Boolean = withContext(Dispatchers.IO) {
        try {
            val response = isoDep.transceive(SELECT_FIDO_APPLET)
            isSuccess(response)
        } catch (e: SecurityException) {
            false
        }
    }

    override suspend fun sendCtapCommand(command: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        try {
            // Wrap CTAP command in ISO 7816-4 APDU
            val apdu = buildApdu(command)

            var response = isoDep.transceive(apdu)

            // Handle response chaining (if response is larger than single frame)
            val fullResponse = mutableListOf<Byte>()

            while (response.size >= 2) {
                val sw1 = response[response.size - 2].toInt() and 0xFF
                val sw2 = response[response.size - 1].toInt() and 0xFF

                // Add data (excluding status bytes)
                if (response.size > 2) {
                    fullResponse.addAll(response.dropLast(2))
                }

                when {
                    sw1 == 0x90 && sw2 == 0x00 -> {
                        // Success - return complete response
                        return@withContext fullResponse.toByteArray()
                    }
                    sw1 == 0x61 -> {
                        // More data available - send GET RESPONSE
                        response = isoDep.transceive(byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, sw2.toByte()))
                    }
                    else -> {
                        // Error
                        throw Exception("APDU error: ${String.format("%02X%02X", sw1, sw2)}")
                    }
                }
            }

            fullResponse.toByteArray()
        } catch (e: TagLostException) {
            close()
            throw e
        } catch (e: SecurityException) {
            // Tag is out of date / disconnected
            throw java.io.IOException("NFC connection lost")
        }
    }

    override fun close() {
        try {
            isoDep.close()
        } catch (e: Exception) {
            // Ignore
        }
    }

    private fun buildApdu(ctapData: ByteArray): ByteArray {
        // NFCCTAP command APDU: CLA=80, INS=10, P1=00, P2=00
        val apdu = mutableListOf<Byte>()
        apdu.add(0x80.toByte())  // CLA
        apdu.add(0x10.toByte())  // INS (NFCCTAP_MSG)
        apdu.add(0x00)           // P1
        apdu.add(0x00)           // P2

        // Lc (length of data) - extended length encoding if needed
        if (ctapData.size <= 255) {
            apdu.add(ctapData.size.toByte())
        } else {
            apdu.add(0x00)
            apdu.add((ctapData.size shr 8).toByte())
            apdu.add((ctapData.size and 0xFF).toByte())
        }

        // Data
        apdu.addAll(ctapData.toList())

        // Le (expected response length) - request maximum
        if (ctapData.size <= 255) {
            apdu.add(0x00)  // Le = 256
        } else {
            apdu.add(0x00)
            apdu.add(0x00)  // Le = 65536
        }

        return apdu.toByteArray()
    }

    private fun isSuccess(response: ByteArray): Boolean {
        return response.size >= 2 &&
                response[response.size - 2] == 0x90.toByte() &&
                response[response.size - 1] == 0x00.toByte()
    }

    companion object {
        // FIDO Alliance AID
        private val SELECT_FIDO_APPLET = byteArrayOf(
            0x00, 0xA4.toByte(), 0x04, 0x00,  // SELECT command
            0x08,                              // Length of AID
            0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,  // FIDO AID
            0x00                               // Le
        )

        /**
         * Connect to a FIDO NFC device via the given NFC tag.
         * Opens the ISO-DEP connection and selects the FIDO applet.
         */
        suspend fun connect(tag: Tag): NfcTransport {
            val isoDep = IsoDep.get(tag) ?: throw AuthnkeyError.NotIsoDepTag()

            if (!isoDep.isConnected) {
                isoDep.connect()
            }
            isoDep.timeout = 5000

            val transport = NfcTransport(isoDep)
            if (!transport.selectFidoApplet()) {
                transport.close()
                throw AuthnkeyError.FidoAppletNotFound()
            }
            return transport
        }
    }
}
