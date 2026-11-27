package pl.lebihan.authnkey

import android.content.Intent
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import org.json.JSONObject

/** A passkey request from Credential Manager. */
internal sealed class PasskeyRequest(
    /** The WebAuthn options. */
    val json: JSONObject,
    val callingAppInfo: CallingAppInfo,
    /** The clientDataHash a privileged caller computed itself, if any. */
    val clientDataHash: ByteArray?,
) {
    abstract val rpId: String
    abstract val userVerification: UserVerification
    /** The pinUvAuthToken permission the operation needs. */
    abstract val pinPermission: Int

    /** The activity result carrying the WebAuthn response. */
    abstract fun responseResult(responseJson: String): Intent

    /** The activity result when the user cancels. */
    abstract fun cancelledResult(): Intent

    class Create(json: JSONObject, callingAppInfo: CallingAppInfo, clientDataHash: ByteArray?) :
        PasskeyRequest(json, callingAppInfo, clientDataHash) {

        override val rpId: String get() = json.getJSONObject("rp").getString("id")
        override val userVerification get() = UserVerification.fromString(
            json.optJSONObject("authenticatorSelection")?.optString("userVerification", "preferred")
        )
        override val pinPermission get() = PinProtocol.PERMISSION_MC

        override fun responseResult(responseJson: String) = Intent().also {
            PendingIntentHandler.setCreateCredentialResponse(it, CreatePublicKeyCredentialResponse(responseJson))
        }

        override fun cancelledResult() = Intent().also {
            PendingIntentHandler.setCreateCredentialException(it, CreateCredentialCancellationException("User cancelled"))
        }
    }

    class Get(json: JSONObject, callingAppInfo: CallingAppInfo, clientDataHash: ByteArray?) :
        PasskeyRequest(json, callingAppInfo, clientDataHash) {

        override val rpId: String get() = json.getString("rpId")
        override val userVerification get() = UserVerification.fromString(
            json.optString("userVerification", "preferred")
        )
        override val pinPermission get() = PinProtocol.PERMISSION_GA

        override fun responseResult(responseJson: String) = Intent().also {
            PendingIntentHandler.setGetCredentialResponse(it, GetCredentialResponse(PublicKeyCredential(responseJson)))
        }

        override fun cancelledResult() = Intent().also {
            PendingIntentHandler.setGetCredentialException(it, GetCredentialCancellationException("User cancelled"))
        }

        /** Discoverable credential requests come without allowCredentials. */
        val isDiscoverable get() = (json.optJSONArray("allowCredentials")?.length() ?: 0) == 0
    }

    companion object {
        fun from(request: ProviderCreateCredentialRequest): Create {
            val publicKeyRequest = request.callingRequest as? CreatePublicKeyCredentialRequest
                ?: throw IllegalArgumentException("Not a passkey creation request")
            return Create(JSONObject(publicKeyRequest.requestJson), request.callingAppInfo, publicKeyRequest.clientDataHash)
        }

        fun from(request: ProviderGetCredentialRequest): Get {
            val option = request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull()
                ?: throw IllegalArgumentException("No passkey option in the request")
            return Get(JSONObject(option.requestJson), request.callingAppInfo, option.clientDataHash)
        }
    }
}

internal enum class UserVerification {
    REQUIRED,
    PREFERRED,
    DISCOURAGED;

    companion object {
        fun fromString(value: String?): UserVerification = when (value) {
            "required" -> REQUIRED
            "discouraged" -> DISCOURAGED
            else -> PREFERRED
        }
    }
}
