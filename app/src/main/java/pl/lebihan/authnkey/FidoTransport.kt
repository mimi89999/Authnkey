package pl.lebihan.authnkey

/**
 * Transport type for FIDO authenticators
 */
enum class TransportType(val webauthnName: String) {
    USB("usb"),
    NFC("nfc")
}

/**
 * Common interface for FIDO transport (NFC or USB)
 */
interface FidoTransport {
    val transportType: TransportType
    val isConnected: Boolean

    /**
     * Verify that the transport connection is still active and usable.
     * Throws [AuthnkeyError.NotConnected] if the connection has been lost
     * (e.g. another app claimed the USB interface, or an NFC tag moved out of range).
     */
    @Throws(AuthnkeyError.NotConnected::class)
    fun reclaimConnection()

    @Throws(Exception::class)
    suspend fun sendCtapCommand(command: ByteArray): ByteArray

    fun close()
}
