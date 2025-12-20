package pl.lebihan.authnkey

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class AuthnkeyCredentialService : CredentialProviderService() {

    companion object {
        private const val TAG = "AuthnkeyCredService"

        const val ACTION_CREATE_PASSKEY = "pl.lebihan.authnkey.CREATE_PASSKEY"
        const val ACTION_GET_PASSKEY = "pl.lebihan.authnkey.GET_PASSKEY"
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        try {
            when (request) {
                is BeginCreatePublicKeyCredentialRequest -> {
                    handleBeginCreatePasskey(request, callback)
                }
                else -> {
                    Log.w(TAG, "Unsupported credential type: ${request.type}")
                    callback.onError(CreateCredentialUnknownException("Unsupported credential type"))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in onBeginCreateCredentialRequest", e)
            callback.onError(CreateCredentialUnknownException(e.message))
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        try {
            val credentialEntries = mutableListOf<CredentialEntry>()

            for (option in request.beginGetCredentialOptions) {
                when (option) {
                    is BeginGetPublicKeyCredentialOption -> {
                        val entries = handleBeginGetPasskey(option)
                        credentialEntries.addAll(entries)
                    }
                }
            }

            val response = BeginGetCredentialResponse.Builder()
                .setCredentialEntries(credentialEntries)
                .build()

            callback.onResult(response)

        } catch (e: Exception) {
            Log.e(TAG, "Error in onBeginGetCredentialRequest", e)
            callback.onError(GetCredentialUnknownException(e.message))
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        // Nothing to clear - credentials are on the physical key
        callback.onResult(null)
    }

    private fun handleBeginCreatePasskey(
        request: BeginCreatePublicKeyCredentialRequest,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        try {
            val json = JSONObject(request.requestJson)
            val rp = json.getJSONObject("rp")
            val rpName = rp.optString("name", rp.getString("id"))

            // Create pending intent to launch our activity
            // The system will attach the full request via PendingIntentHandler
            val intent = Intent(this, CredentialProviderActivity::class.java).apply {
                action = ACTION_CREATE_PASSKEY
            }

            val pendingIntent = PendingIntent.getActivity(
                this,
                System.currentTimeMillis().toInt(),
                intent,
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            val createEntry = CreateEntry.Builder(getString(R.string.credential_entry_title), pendingIntent)
                .setDescription(getString(R.string.credential_create_description, rpName))
                .build()

            val response = BeginCreateCredentialResponse.Builder()
                .setCreateEntries(listOf(createEntry))
                .build()

            callback.onResult(response)

        } catch (e: Exception) {
            Log.e(TAG, "Error parsing create request", e)
            callback.onError(CreateCredentialUnknownException(e.message))
        }
    }

    private fun handleBeginGetPasskey(
        option: BeginGetPublicKeyCredentialOption
    ): List<CredentialEntry> {
        val entries = mutableListOf<CredentialEntry>()

        try {
            val json = JSONObject(option.requestJson)
            val rpId = json.optString("rpId", "")

            // Create pending intent to launch our activity
            // The system will attach the full request via PendingIntentHandler
            val intent = Intent(this, CredentialProviderActivity::class.java).apply {
                action = ACTION_GET_PASSKEY
            }

            val pendingIntent = PendingIntent.getActivity(
                this,
                System.currentTimeMillis().toInt(),
                intent,
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            val entry = PublicKeyCredentialEntry.Builder(
                this,
                getString(R.string.credential_entry_title),
                pendingIntent,
                option
            )
                .setDisplayName(getString(R.string.credential_get_description, rpId))
                .setIcon(Icon.createWithResource(this, R.drawable.security_key_gray_24))
                .build()

            entries.add(entry)

        } catch (e: Exception) {
            Log.e(TAG, "Error parsing get request", e)
        }

        return entries
    }
}
