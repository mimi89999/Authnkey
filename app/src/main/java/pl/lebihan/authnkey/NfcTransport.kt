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

    sealed class TransportError(message: String) : Exception(message) {
        class UnsupportedTransceiveLength(length: Int) :
            TransportError("Unsupported NFC transceive length: $length bytes")

        class ProtocolViolation(detail: String) :
            TransportError("ISO 7816-4 protocol violation: $detail")

        class MessageTooLarge(size: Int, limit: Int) :
            TransportError("Message of $size bytes exceeds the APDU limit of $limit bytes")

        class ApduError(sw: Int) : TransportError(
            "APDU error: ${label(sw)} (0x${sw.toString(16).padStart(4, '0')})"
        ) {
            private companion object {
                fun label(sw: Int) = when (sw) {
                    0x6300 -> "AUTHENTICATION_FAILED"
                    0x6700 -> "WRONG_LENGTH"
                    0x6881 -> "LOGICAL_CHANNEL_NOT_SUPPORTED"
                    0x6884 -> "COMMAND_CHAINING_NOT_SUPPORTED"
                    0x6982 -> "SECURITY_STATUS_NOT_SATISFIED"
                    0x6984 -> "REFERENCE_DATA_INVALID"
                    0x6985 -> "CONDITIONS_NOT_SATISFIED"
                    0x6A80 -> "WRONG_DATA"
                    0x6A81 -> "FUNCTION_NOT_SUPPORTED"
                    0x6A82 -> "FILE_NOT_FOUND"
                    0x6A86 -> "INCORRECT_P1P2"
                    0x6B00 -> "WRONG_P1P2"
                    0x6D00 -> "INS_NOT_SUPPORTED"
                    0x6E00 -> "CLA_NOT_SUPPORTED"
                    0x6F00 -> "NO_PRECISE_DIAGNOSIS"
                    else -> when (sw and 0xFF00) {
                        0x6C00 -> "WRONG_LE"
                        else -> "UNKNOWN"
                    }
                }
            }
        }
    }

    override val transportType = TransportType.NFC

    override val isConnected: Boolean
        get() = try {
            isoDep.isConnected
        } catch (e: SecurityException) {
            false
        }

    // CLA, INS, P1, P2, a 3 byte Lc and a 2 byte Le have to fit alongside the payload
    private val maxMessageSize = minOf(isoDep.maxTransceiveLength - 9, 0xFFFF)

    override fun reclaimConnection() {
        if (!isConnected) {
            throw AuthnkeyError.NotConnected()
        }
    }

    /**
     * Select the FIDO applet on the NFC device, making it the active application.
     */
    private suspend fun selectFidoApplet() = withContext(Dispatchers.IO) {
        val response = try {
            isoDep.transceive(SELECT_FIDO_APPLET)
        } catch (e: Exception) {
            close()
            throw e as? TagLostException
                ?: TagLostException("NFC transfer failed").apply { initCause(e) }
        }

        if (response.size < 2) {
            throw TransportError.ProtocolViolation(
                "SELECT response of ${response.size} bytes carries no status word"
            )
        }

        val sw = statusWord(response)

        if (sw == SW_FILE_NOT_FOUND || sw == SW_APPLET_SELECT_FAILED) {
            throw AuthnkeyError.FidoAppletNotFound()
        }

        if (sw != SW_NO_ERROR) {
            throw TransportError.ApduError(sw)
        }
    }

    override suspend fun sendCtapCommand(command: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        if (command.size > maxMessageSize) {
            throw TransportError.MessageTooLarge(command.size, maxMessageSize)
        }

        // Wrap CTAP command in ISO 7816-4 APDU
        val apdu = buildApdu(command)

        var response = try {
            isoDep.transceive(apdu)
        } catch (e: Exception) {
            close()
            throw e as? TagLostException
                ?: TagLostException("NFC transfer failed").apply { initCause(e) }
        }

        // Handle response chaining (if response is larger than single frame)
        val fullResponse = mutableListOf<Byte>()

        while (true) {
            if (response.size < 2) {
                throw TransportError.ProtocolViolation(
                    "Response of ${response.size} bytes carries no status word"
                )
            }

            // Add data (excluding status bytes)
            val sw = statusWord(response)
            fullResponse.addAll(response.dropLast(2))

            if (fullResponse.size > 0xFFFF) {
                throw TransportError.ProtocolViolation(
                    "Response exceeds the APDU limit of 65535 bytes"
                )
            }

            // Success - the response is complete
            if (sw == SW_NO_ERROR) break

            if ((sw and 0xFF00) != SW1_MORE_DATA) {
                throw TransportError.ApduError(sw)
            }

            // More data available - send GET RESPONSE
            response = try {
                isoDep.transceive(GET_RESPONSE_HEADER + (sw and 0xFF).toByte())
            } catch (e: Exception) {
                close()
                throw e as? TagLostException
                    ?: TagLostException("NFC transfer failed").apply { initCause(e) }
            }
        }

        fullResponse.toByteArray()
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

    private fun statusWord(response: ByteArray): Int =
        ((response[response.size - 2].toInt() and 0xFF) shl 8) or
                (response[response.size - 1].toInt() and 0xFF)

    companion object {
        private const val SW_NO_ERROR = 0x9000
        private const val SW_FILE_NOT_FOUND = 0x6A82
        private const val SW_APPLET_SELECT_FAILED = 0x6999
        private const val SW1_MORE_DATA = 0x6100

        // FIDO Alliance AID
        private val SELECT_FIDO_APPLET = byteArrayOf(
            0x00, 0xA4.toByte(), 0x04, 0x00,  // SELECT command
            0x08,                              // Length of AID
            0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,  // FIDO AID
            0x00                               // Le
        )

        // GET RESPONSE command, Le is appended for each call
        private val GET_RESPONSE_HEADER = byteArrayOf(
            0x00, 0xC0.toByte(), 0x00, 0x00
        )

        /**
         * Connect to a FIDO NFC device via the given NFC tag.
         * Opens the ISO-DEP connection and selects the FIDO applet.
         */
        suspend fun connect(tag: Tag): NfcTransport {
            val isoDep = IsoDep.get(tag) ?: throw AuthnkeyError.NotIsoDepTag()

            if (isoDep.maxTransceiveLength < SELECT_FIDO_APPLET.size) {
                throw TransportError.UnsupportedTransceiveLength(isoDep.maxTransceiveLength)
            }

            if (!isoDep.isConnected) {
                isoDep.connect()
            }
            isoDep.timeout = 5000

            val transport = NfcTransport(isoDep)

            try {
                transport.selectFidoApplet()
            } catch (e: Exception) {
                transport.close()
                throw e
            }
            return transport
        }
    }
}
