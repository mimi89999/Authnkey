package pl.lebihan.authnkey

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * A CTAP session attached to a connected [FidoTransport]. Exposes CTAP
 * operations against a FIDO authenticator.
 */
class CtapSession private constructor(
    val transport: FidoTransport,
    val deviceInfo: DeviceInfo,
) {
    val transportType: TransportType get() = transport.transportType
    val isConnected: Boolean get() = transport.isConnected

    suspend fun sendCtapCommand(command: ByteArray): ByteArray =
        transport.sendCtapCommand(command)

    fun reclaimConnection() = transport.reclaimConnection()

    fun close() = transport.close()

    companion object {
        suspend fun attach(transport: FidoTransport): CtapSession {
            try {
                val infoResponse = withContext(Dispatchers.IO) {
                    transport.sendCtapCommand(CTAP.buildCommand(CTAP.CMD_GET_INFO))
                }
                val deviceInfo = CTAP.parseGetInfoStructured(infoResponse).getOrThrow()
                return CtapSession(transport, deviceInfo)
            } catch (e: Throwable) {
                transport.close()
                throw e
            }
        }
    }
}
