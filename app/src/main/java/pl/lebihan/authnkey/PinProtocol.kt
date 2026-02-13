package pl.lebihan.authnkey

import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class PinProtocol(private val transport: FidoTransport) {

    companion object {
        const val PERMISSION_MC = 0x01
        const val PERMISSION_GA = 0x02
        const val PERMISSION_CM = 0x04
        const val PERMISSION_BE = 0x08
        const val PERMISSION_LBW = 0x10
        const val PERMISSION_ACFG = 0x20
    }

    private var sharedSecret: ByteArray? = null
    private var pinToken: ByteArray? = null
    private var platformPublicKey: ECPublicKey? = null

    suspend fun initialize(): Boolean {
        try {
            val keyAgreementResponse = transport.sendCtapCommand(buildGetKeyAgreementCommand())

            if (!CTAP.isSuccess(keyAgreementResponse)) {
                return false
            }

            val authenticatorPublicKey = parseKeyAgreementResponse(keyAgreementResponse)
                ?: return false

            val keyPairGenerator = KeyPairGenerator.getInstance("EC")
            keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
            val ephemeralKeyPair = keyPairGenerator.generateKeyPair()

            val keyAgreement = KeyAgreement.getInstance("ECDH")
            keyAgreement.init(ephemeralKeyPair.private)
            keyAgreement.doPhase(authenticatorPublicKey, true)
            val rawSharedSecret = keyAgreement.generateSecret()

            val sha256 = MessageDigest.getInstance("SHA-256")
            sharedSecret = sha256.digest(rawSharedSecret)

            platformPublicKey = ephemeralKeyPair.public as ECPublicKey

            return true
        } catch (e: Exception) {
            return false
        }
    }

    suspend fun requestPinToken(pin: String): Result<Unit> {
        val secret = sharedSecret
            ?: return Result.failure(Exception("Shared secret not available"))
        val pubKey = platformPublicKey
            ?: return Result.failure(Exception("Platform key not available"))

        return try {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val pinHash = sha256.digest(pin.toByteArray(Charsets.UTF_8))
            val pinHashLeft16 = pinHash.copyOf(16)

            val encryptedPinHash = aesEncrypt(secret, pinHashLeft16)

            val command = buildGetPinTokenCommand(pubKey, encryptedPinHash)
            val response = transport.sendCtapCommand(command)

            val error = CTAP.getResponseError(response)
            if (error != null) {
                return Result.failure(CTAP.Exception(error))
            }

            val encryptedToken = parsePinTokenResponse(response)
                ?: return Result.failure(Exception("Failed to parse PIN token"))
            pinToken = aesDecrypt(secret, encryptedToken)

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun requestPinToken(pin: String, permissions: Int, rpId: String? = null): Result<Unit> {
        val secret = sharedSecret
            ?: return Result.failure(Exception("Shared secret not available"))
        val pubKey = platformPublicKey
            ?: return Result.failure(Exception("Platform key not available"))

        return try {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val pinHash = sha256.digest(pin.toByteArray(Charsets.UTF_8))
            val pinHashLeft16 = pinHash.copyOf(16)

            val encryptedPinHash = aesEncrypt(secret, pinHashLeft16)

            val command = buildGetPinTokenWithPermissionsCommand(pubKey, encryptedPinHash, permissions, rpId)
            val response = transport.sendCtapCommand(command)

            if (response.isEmpty()) {
                return Result.failure(Exception("Empty response"))
            }

            val error = CTAP.getResponseError(response)
            if (error != null) {
                // Fallback to basic method if authenticator doesn't support permissions
                val fallbackErrors = listOf(
                    CTAP.Error.INVALID_COMMAND,
                    CTAP.Error.INVALID_PARAMETER,
                    CTAP.Error.CBOR_UNEXPECTED_TYPE,
                    CTAP.Error.INVALID_CBOR,
                    CTAP.Error.MISSING_PARAMETER,
                    CTAP.Error.UNSUPPORTED_OPTION,
                    CTAP.Error.INVALID_SUBCOMMAND,
                    CTAP.Error.OTHER
                )
                if (error in fallbackErrors) {
                    return requestPinToken(pin)
                }
                return Result.failure(CTAP.Exception(error))
            }

            val encryptedToken = parsePinTokenResponse(response)
                ?: return Result.failure(Exception("Failed to parse PIN token"))
            pinToken = aesDecrypt(secret, encryptedToken)

            Result.success(Unit)
        } catch (e: java.io.IOException) {
            Result.failure(e)
        } catch (e: Exception) {
            // On unexpected exception, try fallback to basic method
            requestPinToken(pin)
        }
    }

    // CTAP2.1 subCommand 0x06: getPinUvAuthTokenUsingUvWithPermissions
    suspend fun requestUvToken(permissions: Int, rpId: String? = null): Result<Unit> {
        val secret = sharedSecret
            ?: return Result.failure(Exception("Shared secret not available"))
        val pubKey = platformPublicKey
            ?: return Result.failure(Exception("Platform key not available"))

        return try {
            val command = buildGetUvTokenCommand(pubKey, permissions, rpId)
            val response = transport.sendCtapCommand(command)

            if (response.isEmpty()) {
                return Result.failure(Exception("Empty response"))
            }

            val error = CTAP.getResponseError(response)
            if (error != null) {
                return Result.failure(CTAP.Exception(error))
            }

            val encryptedToken = parsePinTokenResponse(response)
                ?: return Result.failure(Exception("Failed to parse UV token"))
            pinToken = aesDecrypt(secret, encryptedToken)

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun getPinRetries(): Result<Int> {
        return try {
            val response = transport.sendCtapCommand(CTAP.buildGetPinRetriesCommand())
            if (!CTAP.isSuccess(response)) {
                return Result.failure(CTAP.Exception(
                    CTAP.getResponseError(response) ?: CTAP.Error.OTHER
                ))
            }

            val data = response.drop(1).toByteArray()
            val parsed = CborMap.decode(data)
                ?: return Result.failure(Exception("Failed to parse response"))
            val retries = parsed.int(3)
                ?: return Result.failure(Exception("Missing retries field"))

            Result.success(retries)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // CTAP2.1 subCommand 0x07: getUvRetries
    suspend fun getUvRetries(): Result<Int> {
        return try {
            val response = transport.sendCtapCommand(CTAP.buildGetUvRetriesCommand())
            if (!CTAP.isSuccess(response)) {
                return Result.failure(CTAP.Exception(
                    CTAP.getResponseError(response) ?: CTAP.Error.OTHER
                ))
            }

            val data = response.drop(1).toByteArray()
            val parsed = CborMap.decode(data)
                ?: return Result.failure(Exception("Failed to parse response"))
            // UV retries are in key 5 per CTAP2.1 spec
            val retries = parsed.int(5)
                ?: return Result.failure(Exception("Missing UV retries field"))

            Result.success(retries)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    sealed class PinSetError(message: String) : Exception(message) {
        class PinAlreadySet : PinSetError("A PIN is already set on this authenticator")
        class PinPolicyViolation : PinSetError("PIN does not meet authenticator requirements")
        class PinBlocked : PinSetError("PIN is blocked")
        data class Other(val errorName: String) : PinSetError(errorName)
    }

    suspend fun setPin(newPin: String): Result<Unit> {
        val secret = sharedSecret ?: return Result.failure(Exception("Shared secret not available"))
        val pubKey = platformPublicKey ?: return Result.failure(Exception("Platform key not available"))

        try {
            val newPinBytes = newPin.toByteArray(Charsets.UTF_8)
            val newPinPadded = ByteArray(64)
            newPinBytes.copyInto(newPinPadded, 0, 0, newPinBytes.size)

            val encryptedNewPin = aesEncrypt(secret, newPinPadded)

            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(secret, "HmacSHA256"))
            val hmacResult = mac.doFinal(encryptedNewPin)
            val pinUvAuthParam = hmacResult.copyOf(16)

            val command = buildSetPinCommand(pubKey, encryptedNewPin, pinUvAuthParam)
            val response = transport.sendCtapCommand(command)

            if (response.isEmpty()) {
                return Result.failure(PinSetError.Other("Empty response"))
            }

            if (CTAP.isSuccess(response)) {
                return Result.success(Unit)
            }

            return when (CTAP.getResponseError(response)) {
                CTAP.Error.PIN_AUTH_INVALID -> Result.failure(PinSetError.PinAlreadySet())
                CTAP.Error.NOT_ALLOWED -> Result.failure(PinSetError.PinAlreadySet())
                CTAP.Error.PIN_POLICY_VIOLATION -> Result.failure(PinSetError.PinPolicyViolation())
                CTAP.Error.PIN_BLOCKED -> Result.failure(PinSetError.PinBlocked())
                else -> Result.failure(PinSetError.Other(CTAP.getErrorName(response[0])))
            }

        } catch (e: Exception) {
            return Result.failure(e)
        }
    }

    sealed class PinChangeError(message: String) : Exception(message) {
        class InvalidPin : PinChangeError("Current PIN is incorrect")
        class PinBlocked : PinChangeError("PIN is blocked due to too many incorrect attempts")
        class PinPolicyViolation : PinChangeError("New PIN does not meet authenticator requirements")
        class PinNotSet : PinChangeError("No PIN is set on this authenticator")
        data class Other(val errorName: String) : PinChangeError(errorName)
    }

    suspend fun changePin(currentPin: String, newPin: String): Result<Unit> {
        val secret = sharedSecret ?: return Result.failure(Exception("Shared secret not available"))
        val pubKey = platformPublicKey ?: return Result.failure(Exception("Platform key not available"))

        try {
            val sha256 = MessageDigest.getInstance("SHA-256")

            val currentPinHash = sha256.digest(currentPin.toByteArray(Charsets.UTF_8))
            val currentPinHashLeft16 = currentPinHash.copyOf(16)

            val newPinBytes = newPin.toByteArray(Charsets.UTF_8)
            val newPinPadded = ByteArray(64)
            newPinBytes.copyInto(newPinPadded, 0, 0, newPinBytes.size)

            val encryptedCurrentPinHash = aesEncrypt(secret, currentPinHashLeft16)
            val encryptedNewPin = aesEncrypt(secret, newPinPadded)

            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(secret, "HmacSHA256"))
            mac.update(encryptedNewPin)
            mac.update(encryptedCurrentPinHash)
            val hmacResult = mac.doFinal()
            val pinUvAuthParam = hmacResult.copyOf(16)

            val command = buildChangePinCommand(pubKey, encryptedNewPin, encryptedCurrentPinHash, pinUvAuthParam)
            val response = transport.sendCtapCommand(command)

            if (response.isEmpty()) {
                return Result.failure(PinChangeError.Other("Empty response"))
            }

            if (CTAP.isSuccess(response)) {
                return Result.success(Unit)
            }

            return when (CTAP.getResponseError(response)) {
                CTAP.Error.PIN_INVALID -> Result.failure(PinChangeError.InvalidPin())
                CTAP.Error.PIN_BLOCKED -> Result.failure(PinChangeError.PinBlocked())
                CTAP.Error.PIN_POLICY_VIOLATION -> Result.failure(PinChangeError.PinPolicyViolation())
                CTAP.Error.PIN_NOT_SET -> Result.failure(PinChangeError.PinNotSet())
                else -> Result.failure(PinChangeError.Other(CTAP.getErrorName(response[0])))
            }

        } catch (e: Exception) {
            return Result.failure(e)
        }
    }

    fun hasPinToken(): Boolean = pinToken != null

    fun computeAuthParam(message: ByteArray): ByteArray? {
        val token = pinToken ?: return null

        try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(token, "HmacSHA256"))
            val hmacResult = mac.doFinal(message)
            return hmacResult.copyOf(16)
        } catch (e: Exception) {
            return null
        }
    }

    private fun buildGetKeyAgreementCommand(): ByteArray {
        return byteArrayOf(CTAP.CMD_CLIENT_PIN.toByte()) + cbor {
            map {
                1 to 1
                2 to 2
            }
        }
    }

    private fun buildGetPinTokenCommand(platformKey: ECPublicKey, encryptedPinHash: ByteArray): ByteArray {
        return byteArrayOf(CTAP.CMD_CLIENT_PIN.toByte()) + cbor {
            map {
                1 to 1
                2 to 5
                3 to encodeCoseKey(platformKey)
                6 to bytes(encryptedPinHash)
            }
        }
    }

    private fun buildGetPinTokenWithPermissionsCommand(
        platformKey: ECPublicKey,
        encryptedPinHash: ByteArray,
        permissions: Int,
        rpId: String? = null
    ): ByteArray {
        return byteArrayOf(CTAP.CMD_CLIENT_PIN.toByte()) + cbor {
            map {
                1 to 1
                2 to 9
                3 to encodeCoseKey(platformKey)
                6 to bytes(encryptedPinHash)
                9 to permissions
                if (rpId != null) {
                    0x0A to rpId
                }
            }
        }
    }

    // subCommand 0x06 — no PIN hash, authenticator performs UV internally
    private fun buildGetUvTokenCommand(
        platformKey: ECPublicKey,
        permissions: Int,
        rpId: String? = null
    ): ByteArray {
        return byteArrayOf(CTAP.CMD_CLIENT_PIN.toByte()) + cbor {
            map {
                1 to 1  // pinUvAuthProtocol
                2 to CTAP.PIN_CMD_GET_PIN_UV_TOKEN_USING_UV  // subCommand 0x06
                3 to encodeCoseKey(platformKey)  // keyAgreement
                9 to permissions  // permissions
                if (rpId != null) {
                    0x0A to rpId  // rpId
                }
            }
        }
    }

    private fun buildSetPinCommand(
        platformKey: ECPublicKey,
        encryptedNewPin: ByteArray,
        pinUvAuthParam: ByteArray
    ): ByteArray {
        return byteArrayOf(CTAP.CMD_CLIENT_PIN.toByte()) + cbor {
            map {
                1 to 1
                2 to 3  // subCommand: setPin
                3 to encodeCoseKey(platformKey)
                4 to bytes(pinUvAuthParam)
                5 to bytes(encryptedNewPin)
            }
        }
    }

    private fun buildChangePinCommand(
        platformKey: ECPublicKey,
        encryptedNewPin: ByteArray,
        encryptedCurrentPinHash: ByteArray,
        pinUvAuthParam: ByteArray
    ): ByteArray {
        return byteArrayOf(CTAP.CMD_CLIENT_PIN.toByte()) + cbor {
            map {
                1 to 1
                2 to 4
                3 to encodeCoseKey(platformKey)
                4 to bytes(pinUvAuthParam)
                5 to bytes(encryptedNewPin)
                6 to bytes(encryptedCurrentPinHash)
            }
        }
    }

    private fun CborMapEncoder.encodeCoseKey(publicKey: ECPublicKey): CborRaw {
        val point = publicKey.w
        val x = bigIntegerToBytes(point.affineX, 32)
        val y = bigIntegerToBytes(point.affineY, 32)

        return map {
            1 to 2
            3 to -25
            -1 to 1
            -2 to bytes(x)
            -3 to bytes(y)
        }
    }

    private fun parseKeyAgreementResponse(response: ByteArray): ECPublicKey? {
        try {
            val data = response.drop(1).toByteArray()
            val parsed = CborMap.decode(data) ?: return null

            val coseKey = parsed.map(1) ?: return null

            val x = coseKey.bytes(-2) ?: return null
            val y = coseKey.bytes(-3) ?: return null

            return createECPublicKey(x, y)
        } catch (e: Exception) {
            return null
        }
    }

    private fun parsePinTokenResponse(response: ByteArray): ByteArray? {
        try {
            val data = response.drop(1).toByteArray()
            val parsed = CborMap.decode(data) ?: return null

            return parsed.bytes(2)
        } catch (e: Exception) {
            return null
        }
    }

    private fun aesEncrypt(key: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        val secretKey = SecretKeySpec(key, "AES")
        val iv = IvParameterSpec(ByteArray(16))
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv)
        return cipher.doFinal(data)
    }

    private fun aesDecrypt(key: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        val secretKey = SecretKeySpec(key, "AES")
        val iv = IvParameterSpec(ByteArray(16))
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv)
        return cipher.doFinal(data)
    }

    private fun createECPublicKey(x: ByteArray, y: ByteArray): ECPublicKey {
        val ecPoint = ECPoint(BigInteger(1, x), BigInteger(1, y))

        val paramSpec = ECGenParameterSpec("secp256r1")
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(paramSpec)
        val params = (keyPairGenerator.generateKeyPair().public as ECPublicKey).params

        val pubKeySpec = ECPublicKeySpec(ecPoint, params)
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(pubKeySpec) as ECPublicKey
    }

    private fun bigIntegerToBytes(value: BigInteger, length: Int): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == length -> bytes
            bytes.size > length -> bytes.copyOfRange(bytes.size - length, bytes.size)
            else -> ByteArray(length - bytes.size) + bytes
        }
    }
}
