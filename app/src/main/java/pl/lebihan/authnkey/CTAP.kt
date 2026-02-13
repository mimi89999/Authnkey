package pl.lebihan.authnkey

data class AlgorithmInfo(
    val type: String?,
    val alg: Int?
)

data class AttestedCredentialData(
    val aaguid: ByteArray,
    val credentialId: ByteArray,
    val credentialPublicKey: Map<*, *>
) {
    val publicKeyAlgorithm: Int?
        get() = (credentialPublicKey[3L] as? Number)?.toInt()

    val keyType: Int?
        get() = (credentialPublicKey[1L] as? Number)?.toInt()

    val curve: Int?
        get() = (credentialPublicKey[-1L] as? Number)?.toInt()
}

data class AuthenticatorData(
    val rpIdHash: ByteArray,
    val flags: Int,
    val signCount: Long,
    val attestedCredentialData: AttestedCredentialData?
) {
    val userPresent: Boolean
        get() = (flags and CTAP.AUTH_DATA_FLAG_UP) != 0

    val userVerified: Boolean
        get() = (flags and CTAP.AUTH_DATA_FLAG_UV) != 0

    val hasAttestedCredentialData: Boolean
        get() = (flags and CTAP.AUTH_DATA_FLAG_AT) != 0

    val hasExtensions: Boolean
        get() = (flags and CTAP.AUTH_DATA_FLAG_ED) != 0

    companion object {
        fun parse(data: ByteArray): AuthenticatorData? {
            if (data.size < 37) return null

            val rpIdHash = data.sliceArray(0 until 32)
            val flags = data[32].toInt() and 0xFF
            val signCount = ((data[33].toLong() and 0xFF) shl 24) or
                    ((data[34].toLong() and 0xFF) shl 16) or
                    ((data[35].toLong() and 0xFF) shl 8) or
                    (data[36].toLong() and 0xFF)

            var offset = 37
            val hasAt = (flags and CTAP.AUTH_DATA_FLAG_AT) != 0

            val attestedCredentialData = if (hasAt) {
                if (data.size < offset + 18) return null

                val aaguid = data.sliceArray(offset until offset + 16)
                offset += 16

                val credIdLen = ((data[offset].toInt() and 0xFF) shl 8) or
                        (data[offset + 1].toInt() and 0xFF)
                offset += 2

                if (data.size < offset + credIdLen) return null
                val credentialId = data.sliceArray(offset until offset + credIdLen)
                offset += credIdLen

                val credentialPublicKey = CborDecoder.decode(
                    data.sliceArray(offset until data.size)
                ) as? Map<*, *> ?: return null

                AttestedCredentialData(aaguid, credentialId, credentialPublicKey)
            } else null

            return AuthenticatorData(rpIdHash, flags, signCount, attestedCredentialData)
        }
    }
}

data class DeviceInfo(
    val versions: List<String> = emptyList(),
    val extensions: List<String> = emptyList(),
    val aaguid: ByteArray? = null,
    val options: Map<String, Boolean> = emptyMap(),
    val maxMsgSize: Int? = null,
    val pinUvAuthProtocols: List<Int> = emptyList(),
    val maxCredentialCountInList: Int? = null,
    val maxCredentialIdLength: Int? = null,
    val transports: List<String> = emptyList(),
    val algorithms: List<AlgorithmInfo> = emptyList(),
    val firmwareVersion: Int? = null,
    val minPinLength: Int? = null
) {
    val supportsCredMgmt: Boolean
        get() = options["credMgmt"] == true

    val supportsCredMgmtPreview: Boolean
        get() = options["credentialMgmtPreview"] == true

    val usePreviewCommand: Boolean
        get() = supportsCredMgmtPreview && !supportsCredMgmt

    val clientPinSet: Boolean
        get() = options["clientPin"] == true

    val supportsBuiltInUv: Boolean
        get() = options["uv"] == true
}

object CTAP {
    // Commands
    const val CMD_MAKE_CREDENTIAL = 0x01
    const val CMD_GET_ASSERTION = 0x02
    const val CMD_GET_INFO = 0x04
    const val CMD_CLIENT_PIN = 0x06
    const val CMD_RESET = 0x07
    const val CMD_GET_NEXT_ASSERTION = 0x08
    const val CMD_CREDENTIAL_MANAGEMENT = 0x0A
    const val CMD_CREDENTIAL_MANAGEMENT_PREVIEW = 0x41
    const val CMD_SELECTION = 0x0B
    const val CMD_LARGE_BLOBS = 0x0C
    const val CMD_CONFIG = 0x0D

    const val PIN_CMD_GET_RETRIES = 0x01
    const val PIN_CMD_GET_KEY_AGREEMENT = 0x02
    const val PIN_CMD_SET_PIN = 0x03
    const val PIN_CMD_CHANGE_PIN = 0x04
    const val PIN_CMD_GET_PIN_TOKEN = 0x05
    const val PIN_CMD_GET_PIN_UV_TOKEN_USING_UV = 0x06
    const val PIN_CMD_GET_UV_RETRIES = 0x07
    const val PIN_CMD_GET_PIN_UV_TOKEN_USING_PIN = 0x09

    // AuthData flags
    const val AUTH_DATA_FLAG_UP = 0x01  // User present
    const val AUTH_DATA_FLAG_UV = 0x04  // User verified
    const val AUTH_DATA_FLAG_AT = 0x40  // Attested credential data present
    const val AUTH_DATA_FLAG_ED = 0x80  // Extension data present

    // COSE key types
    const val COSE_KTY_OKP = 1
    const val COSE_KTY_EC2 = 2

    // COSE curves
    const val COSE_CRV_P256 = 1
    const val COSE_CRV_ED25519 = 6

    private const val STATUS_SUCCESS: Byte = 0x00

    enum class Error(val code: Int) {
        SUCCESS(0x00),
        INVALID_COMMAND(0x01),
        INVALID_PARAMETER(0x02),
        INVALID_LENGTH(0x03),
        INVALID_SEQ(0x04),
        TIMEOUT(0x05),
        CHANNEL_BUSY(0x06),
        LOCK_REQUIRED(0x0A),
        INVALID_CHANNEL(0x0B),
        CBOR_UNEXPECTED_TYPE(0x11),
        INVALID_CBOR(0x12),
        MISSING_PARAMETER(0x14),
        LIMIT_EXCEEDED(0x15),
        CREDENTIAL_EXCLUDED(0x19),
        PROCESSING(0x21),
        INVALID_CREDENTIAL(0x22),
        USER_ACTION_PENDING(0x23),
        OPERATION_PENDING(0x24),
        NO_OPERATIONS(0x25),
        UNSUPPORTED_ALGORITHM(0x26),
        OPERATION_DENIED(0x27),
        KEY_STORE_FULL(0x28),
        UNSUPPORTED_OPTION(0x2B),
        INVALID_OPTION(0x2C),
        KEEPALIVE_CANCEL(0x2D),
        NO_CREDENTIALS(0x2E),
        USER_ACTION_TIMEOUT(0x2F),
        NOT_ALLOWED(0x30),
        PIN_INVALID(0x31),
        PIN_BLOCKED(0x32),
        PIN_AUTH_INVALID(0x33),
        PIN_AUTH_BLOCKED(0x34),
        PIN_NOT_SET(0x35),
        PIN_REQUIRED(0x36),
        PIN_POLICY_VIOLATION(0x37),
        PIN_TOKEN_EXPIRED(0x38),
        REQUEST_TOO_LARGE(0x39),
        ACTION_TIMEOUT(0x3A),
        UP_REQUIRED(0x3B),
        UV_BLOCKED(0x3C),
        INTEGRITY_FAILURE(0x3D),
        INVALID_SUBCOMMAND(0x3E),
        UV_INVALID(0x3F),
        UNAUTHORIZED_PERMISSION(0x40),
        OTHER(0x7F);

        companion object {
            private val byCode = entries.associateBy { it.code }
            fun fromCode(code: Int): Error? = byCode[code]
        }
    }

    class Exception(val error: Error) : kotlin.Exception(error.name)

    fun getErrorName(code: Byte): String {
        val intCode = code.toInt() and 0xFF
        return Error.fromCode(intCode)?.name ?: "UNKNOWN_ERROR (0x${String.format("%02X", code)})"
    }

    fun isSuccess(response: ByteArray): Boolean {
        return response.isNotEmpty() && response[0] == STATUS_SUCCESS
    }

    fun getResponseError(response: ByteArray): Error? {
        if (response.isEmpty()) return Error.OTHER
        val code = response[0].toInt() and 0xFF
        return if (code == 0) null else (Error.fromCode(code) ?: Error.OTHER)
    }

    fun getResponseErrorMessage(response: ByteArray): String? {
        if (response.isEmpty()) return "Empty response"
        val code = response[0].toInt() and 0xFF
        return if (code == 0) null else getErrorName(response[0])
    }

    fun buildCommand(cmd: Int): ByteArray {
        return byteArrayOf(cmd.toByte())
    }

    fun parseGetInfoStructured(response: ByteArray): DeviceInfo? {
        if (!isSuccess(response)) {
            return null
        }

        val data = response.drop(1).toByteArray()

        return try {
            val parsed = CborMap.decode(data) ?: return null

            val versions = parsed.list<String>(1) ?: emptyList()
            val extensions = parsed.list<String>(2) ?: emptyList()
            val aaguid = parsed.bytes(3)

            val options = mutableMapOf<String, Boolean>()
            parsed.map(4)?.let { opts ->
                val raw = CborDecoder.decode(data) as? Map<*, *>
                (raw?.get(4L) as? Map<*, *>)?.forEach { (k, v) ->
                    if (k is String && v is Boolean) {
                        options[k] = v
                    }
                }
            }

            val maxMsgSize = parsed.int(5)
            val pinUvAuthProtocols = parsed.list<Long>(6)?.map { it.toInt() } ?: emptyList()
            val maxCredentialCountInList = parsed.int(7)
            val maxCredentialIdLength = parsed.int(8)
            val transports = parsed.list<String>(9) ?: emptyList()

            val algorithms = parsed.mapList(10)?.mapNotNull { alg ->
                AlgorithmInfo(
                    type = alg.string("type"),
                    alg = alg.int("alg")
                )
            } ?: emptyList()

            val minPinLength = parsed.int(13)
            val firmwareVersion = parsed.int(14)

            DeviceInfo(
                versions = versions,
                extensions = extensions,
                aaguid = aaguid,
                options = options,
                maxMsgSize = maxMsgSize,
                pinUvAuthProtocols = pinUvAuthProtocols,
                maxCredentialCountInList = maxCredentialCountInList,
                maxCredentialIdLength = maxCredentialIdLength,
                transports = transports,
                algorithms = algorithms,
                firmwareVersion = firmwareVersion,
                minPinLength = minPinLength
            )
        } catch (e: Exception) {
            null
        }
    }

    fun buildGetPinRetriesCommand(): ByteArray {
        return byteArrayOf(CMD_CLIENT_PIN.toByte()) + cbor {
            map {
                1 to 1
                2 to 1
            }
        }
    }

    fun buildGetUvRetriesCommand(): ByteArray {
        return byteArrayOf(CMD_CLIENT_PIN.toByte()) + cbor {
            map {
                1 to 1
                2 to PIN_CMD_GET_UV_RETRIES
            }
        }
    }
}
