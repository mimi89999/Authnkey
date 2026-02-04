package pl.lebihan.authnkey

import java.security.MessageDigest

object FidoCommands {

    fun buildMakeCredential(
        clientDataHash: ByteArray,
        rpId: String,
        rpName: String?,
        userId: ByteArray,
        userName: String?,
        userDisplayName: String?,
        pubKeyCredParams: List<Pair<String, Int>>,
        excludeList: List<ByteArray>? = null,
        requireResidentKey: Boolean = true,
        requireUserVerification: Boolean = true,
        pinUvAuthParam: ByteArray? = null,
        pinUvAuthProtocol: Int? = null
    ): ByteArray {
        val payload = cbor {
            map {
                1 to bytes(clientDataHash)

                2 to map {
                    "id" to rpId
                    if (rpName != null) "name" to rpName
                }

                3 to map {
                    "id" to bytes(userId)
                    if (userName != null) "name" to userName
                    if (userDisplayName != null) "displayName" to userDisplayName
                }

                4 to array {
                    for ((type, alg) in pubKeyCredParams) {
                        map {
                            "alg" to alg
                            "type" to type
                        }
                    }
                }

                if (excludeList != null && excludeList.isNotEmpty()) {
                    5 to array {
                        for (credId in excludeList) {
                            map {
                                "type" to "public-key"
                                "id" to bytes(credId)
                            }
                        }
                    }
                }

                7 to map { "rk" to requireResidentKey }

                if (pinUvAuthParam != null) {
                    8 to bytes(pinUvAuthParam)
                }

                if (pinUvAuthProtocol != null) {
                    9 to pinUvAuthProtocol
                }
            }
        }

        return byteArrayOf(CTAP.CMD_MAKE_CREDENTIAL.toByte()) + payload
    }

    fun buildGetAssertion(
        rpId: String,
        clientDataHash: ByteArray,
        allowList: List<ByteArray>? = null,
        requireUserVerification: Boolean = true,
        pinUvAuthParam: ByteArray? = null,
        pinUvAuthProtocol: Int? = null
    ): ByteArray {
        val payload = cbor {
            map {
                1 to rpId
                2 to bytes(clientDataHash)

                if (allowList != null && allowList.isNotEmpty()) {
                    3 to array {
                        for (credId in allowList) {
                            map {
                                "type" to "public-key"
                                "id" to bytes(credId)
                            }
                        }
                    }
                }

                5 to map { "up" to true }

                if (pinUvAuthParam != null) {
                    6 to bytes(pinUvAuthParam)
                }

                if (pinUvAuthProtocol != null) {
                    7 to pinUvAuthProtocol
                }
            }
        }

        return byteArrayOf(CTAP.CMD_GET_ASSERTION.toByte()) + payload
    }

    fun buildGetNextAssertion(): ByteArray {
        return byteArrayOf(CTAP.CMD_GET_NEXT_ASSERTION.toByte())
    }

    data class MakeCredentialResponse(
        val fmt: String,
        val authData: ByteArray,
        val attStmt: Map<*, *>,
        val rawResponse: ByteArray
    )

    fun parseMakeCredentialResponse(response: ByteArray): Result<MakeCredentialResponse> {
        val error = CTAP.getResponseError(response)
        if (error != null) {
            return Result.failure(CTAP.Exception(error))
        }

        return try {
            val data = response.drop(1).toByteArray()
            val parsed = CborMap.decode(data)
                ?: return Result.failure(Exception("Invalid CBOR"))

            val fmt = parsed.string(1)
                ?: return Result.failure(Exception("Missing fmt"))
            val authData = parsed.bytes(2)
                ?: return Result.failure(Exception("Missing authData"))

            val rawDecoded = CborDecoder.decode(data) as? Map<*, *>
                ?: return Result.failure(Exception("Invalid CBOR"))
            val attStmt = (rawDecoded[3L] ?: rawDecoded[3]) as? Map<*, *>
                ?: return Result.failure(Exception("Missing attStmt"))

            Result.success(MakeCredentialResponse(fmt, authData, attStmt, data))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    data class GetAssertionResponse(
        val credential: CredentialDescriptor?,
        val authData: ByteArray,
        val signature: ByteArray,
        val user: UserEntity?,
        val numberOfCredentials: Int?,
        val rawResponse: ByteArray
    )

    data class CredentialDescriptor(
        val type: String,
        val id: ByteArray
    )

    data class UserEntity(
        val id: ByteArray,
        val name: String?,
        val displayName: String?
    )

    fun parseGetAssertionResponse(response: ByteArray): Result<GetAssertionResponse> {
        val error = CTAP.getResponseError(response)
        if (error != null) {
            return Result.failure(CTAP.Exception(error))
        }

        return try {
            val data = response.drop(1).toByteArray()
            val parsed = CborMap.decode(data)
                ?: return Result.failure(Exception("Invalid CBOR"))

            val credentialMap = parsed.map(1)
            val credential = credentialMap?.let {
                CredentialDescriptor(
                    type = it.string("type") ?: "public-key",
                    id = it.bytes("id") ?: ByteArray(0)
                )
            }

            val authData = parsed.bytes(2)
                ?: return Result.failure(Exception("Missing authData"))

            val signature = parsed.bytes(3)
                ?: return Result.failure(Exception("Missing signature"))

            val userMap = parsed.map(4)
            val user = userMap?.let {
                UserEntity(
                    id = it.bytes("id") ?: ByteArray(0),
                    name = it.string("name"),
                    displayName = it.string("displayName")
                )
            }

            val numberOfCredentials = parsed.int(5)

            Result.success(GetAssertionResponse(
                credential = credential,
                authData = authData,
                signature = signature,
                user = user,
                numberOfCredentials = numberOfCredentials,
                rawResponse = data
            ))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun hashClientData(clientDataJson: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(clientDataJson.toByteArray(Charsets.UTF_8))
    }

    fun hashRpId(rpId: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(rpId.toByteArray(Charsets.UTF_8))
    }
}
