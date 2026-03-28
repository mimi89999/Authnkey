package pl.lebihan.authnkey

class CredentialManagement(
    private val transport: FidoTransport,
    private val authToken: PinProtocol.Authenticated,
    private val usePreviewCommand: Boolean = false
) {

    private val credMgmtCommand: Byte = if (usePreviewCommand)
        CTAP.CMD_CREDENTIAL_MANAGEMENT_PREVIEW.toByte()
    else
        CTAP.CMD_CREDENTIAL_MANAGEMENT.toByte()

    companion object {
        const val CMD_GET_CREDS_METADATA = 0x01
        const val CMD_ENUMERATE_RPS_BEGIN = 0x02
        const val CMD_ENUMERATE_RPS_NEXT = 0x03
        const val CMD_ENUMERATE_CREDS_BEGIN = 0x04
        const val CMD_ENUMERATE_CREDS_NEXT = 0x05
        const val CMD_DELETE_CREDENTIAL = 0x06
        const val CMD_UPDATE_USER_INFO = 0x07
    }

    data class RelyingParty(
        val rpIdHash: ByteArray,
        val rpId: String?,
        val rpName: String?,
        val totalCredentials: Int?
    )

    data class Credential(
        val credentialId: ByteArray,
        val rpId: String?,
        val userId: ByteArray?,
        val userName: String?,
        val userDisplayName: String?,
        val publicKey: Map<*, *>?,
        val credProtect: Int?,
        val largeBlobKey: ByteArray?
    )

    data class CredentialMetadata(
        val existingResidentCredentialsCount: Int,
        val maxPossibleRemainingCredentials: Int
    )

    suspend fun getCredentialsMetadata(): Result<CredentialMetadata> {
        try {
            val command = buildCredMgmtCommand(CMD_GET_CREDS_METADATA, null)
            val response = transport.sendCtapCommand(command)

            val error = CTAP.getResponseError(response)
            if (error != null) {
                return Result.failure(CTAP.Exception(error))
            }

            val data = response.drop(1).toByteArray()
            val parsed = CborMap.decode(data)
                ?: return Result.failure(Exception("Invalid CBOR response"))

            val existing = parsed.int(1) ?: 0
            val remaining = parsed.int(2) ?: 0

            return Result.success(CredentialMetadata(existing, remaining))

        } catch (e: Exception) {
            return Result.failure(e)
        }
    }

    suspend fun enumerateRelyingParties(): Result<List<RelyingParty>> {
        val relyingParties = mutableListOf<RelyingParty>()

        try {
            val beginCommand = buildCredMgmtCommand(CMD_ENUMERATE_RPS_BEGIN, null)
            val beginResponse = transport.sendCtapCommand(beginCommand)

            val error = CTAP.getResponseError(beginResponse)
            if (error != null) {
                if (error == CTAP.Error.NO_CREDENTIALS) {
                    return Result.success(emptyList())
                }
                return Result.failure(CTAP.Exception(error))
            }

            val firstRp = parseRelyingPartyResponse(beginResponse)
            if (firstRp != null) {
                relyingParties.add(firstRp.first)

                val totalRps = firstRp.second
                for (i in 1 until totalRps) {
                    val nextCommand = buildCredMgmtCommand(CMD_ENUMERATE_RPS_NEXT, null, includeAuth = false)
                    val nextResponse = transport.sendCtapCommand(nextCommand)

                    if (CTAP.isSuccess(nextResponse)) {
                        parseRelyingPartyResponse(nextResponse)?.let { (rp, _) ->
                            relyingParties.add(rp)
                        }
                    }
                }
            }

            return Result.success(relyingParties)

        } catch (e: Exception) {
            return Result.failure(e)
        }
    }

    suspend fun enumerateCredentials(rpIdHash: ByteArray): Result<List<Credential>> {
        val credentials = mutableListOf<Credential>()

        try {
            val params = buildRpIdHashParam(rpIdHash)

            val beginCommand = buildCredMgmtCommand(CMD_ENUMERATE_CREDS_BEGIN, params)
            val beginResponse = transport.sendCtapCommand(beginCommand)

            val error = CTAP.getResponseError(beginResponse)
            if (error != null) {
                if (error == CTAP.Error.NO_CREDENTIALS) {
                    return Result.success(emptyList())
                }
                return Result.failure(CTAP.Exception(error))
            }

            val firstCred = parseCredentialResponse(beginResponse)
            if (firstCred != null) {
                credentials.add(firstCred.first)

                val totalCreds = firstCred.second
                for (i in 1 until totalCreds) {
                    val nextCommand = buildCredMgmtCommand(CMD_ENUMERATE_CREDS_NEXT, null, includeAuth = false)
                    val nextResponse = transport.sendCtapCommand(nextCommand)

                    if (CTAP.isSuccess(nextResponse)) {
                        parseCredentialResponse(nextResponse)?.let { (cred, _) ->
                            credentials.add(cred)
                        }
                    }
                }
            }

            return Result.success(credentials)

        } catch (e: Exception) {
            return Result.failure(e)
        }
    }

    suspend fun deleteCredential(credentialId: ByteArray): Result<Unit> {
        try {
            val params = buildCredentialIdParam(credentialId)
            val command = buildCredMgmtCommand(CMD_DELETE_CREDENTIAL, params)
            val response = transport.sendCtapCommand(command)

            val error = CTAP.getResponseError(response)
            if (error != null) {
                return Result.failure(CTAP.Exception(error))
            }

            return Result.success(Unit)

        } catch (e: Exception) {
            return Result.failure(e)
        }
    }

    private fun buildCredMgmtCommand(
        subCommand: Int,
        subCommandParams: ByteArray?,
        includeAuth: Boolean = true
    ): ByteArray {
        val authParam = if (includeAuth) {
            val authMessage = mutableListOf<Byte>()
            authMessage.add(subCommand.toByte())
            if (subCommandParams != null) {
                authMessage.addAll(subCommandParams.toList())
            }
            authToken.computeAuthParam(authMessage.toByteArray())
        } else null

        val payload = cbor {
            map {
                1 to subCommand

                if (subCommandParams != null) {
                    2 to CborRaw(subCommandParams.toList())
                }

                if (includeAuth && authParam != null) {
                    3 to 1
                    4 to bytes(authParam)
                }
            }
        }

        return byteArrayOf(credMgmtCommand) + payload
    }

    private fun buildRpIdHashParam(rpIdHash: ByteArray): ByteArray {
        return cbor {
            map {
                1 to bytes(rpIdHash)
            }
        }
    }

    private fun buildCredentialIdParam(credentialId: ByteArray): ByteArray {
        return cbor {
            map {
                2 to map {
                    "type" to "public-key"
                    "id" to bytes(credentialId)
                }
            }
        }
    }

    private fun parseRelyingPartyResponse(response: ByteArray): Pair<RelyingParty, Int>? {
        try {
            val data = response.drop(1).toByteArray()
            val parsed = CborMap.decode(data) ?: return null

            val rp = parsed.map(3)
            val rpId = rp?.string("id")
            val rpName = rp?.string("name")

            val rpIdHash = parsed.bytes(4) ?: return null

            val totalRps = parsed.int(5) ?: 1

            return Pair(
                RelyingParty(rpIdHash, rpId, rpName, null),
                totalRps
            )
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    private fun parseCredentialResponse(response: ByteArray): Pair<Credential, Int>? {
        try {
            val data = response.drop(1).toByteArray()
            val parsed = CborMap.decode(data) ?: return null

            val user = parsed.map(6)
            val userId = user?.bytes("id")
            val userName = user?.string("name")
            val userDisplayName = user?.string("displayName")

            val credDesc = parsed.map(7)
            val credentialId = credDesc?.bytes("id") ?: return null

            val rawDecoded = CborDecoder.decode(data) as? Map<*, *>
            val publicKey = (rawDecoded?.get(8L) ?: rawDecoded?.get(8)) as? Map<*, *>

            val totalCreds = parsed.int(9) ?: 1

            val credProtect = parsed.int(10)

            val largeBlobKey = parsed.bytes(11)

            return Pair(
                Credential(
                    credentialId = credentialId,
                    rpId = null,
                    userId = userId,
                    userName = userName,
                    userDisplayName = userDisplayName,
                    publicKey = publicKey,
                    credProtect = credProtect,
                    largeBlobKey = largeBlobKey
                ),
                totalCreds
            )
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
}
