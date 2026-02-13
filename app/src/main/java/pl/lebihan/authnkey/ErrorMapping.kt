package pl.lebihan.authnkey

import android.content.Context
import android.nfc.TagLostException

fun Throwable.toUserMessage(context: Context): String = when (this) {
    // Android NFC exception
    is TagLostException -> context.getString(R.string.error_tag_lost)

    // CTAP protocol errors
    is CTAP.Exception -> this.error.toUserMessage(context)

    // App-specific errors
    is AuthnkeyError.NotIsoDepTag -> context.getString(R.string.error_not_supported_tag)
    is AuthnkeyError.FidoAppletNotFound -> context.getString(R.string.error_not_security_key)
    is AuthnkeyError.ConnectionFailed -> context.getString(R.string.error_connection_failed)
    is AuthnkeyError.NotConnected -> context.getString(R.string.error_not_connected)
    is AuthnkeyError.PinProtocolNotInitialized -> context.getString(R.string.error_key_disconnected)
    is AuthnkeyError.PinProtocolInitFailed -> context.getString(R.string.error_communication_failed)
    is AuthnkeyError.UserVerificationRequiredNoPin -> context.getString(R.string.error_uv_required_no_pin)
    is AuthnkeyError.PinBlocked -> context.getString(R.string.error_pin_blocked)
    is AuthnkeyError.UvBlocked -> context.getString(R.string.error_uv_blocked)

    // Fallback
    else -> this.message ?: context.getString(R.string.error_unknown)
}

private fun CTAP.Error.toUserMessage(context: Context): String = when (this) {
    CTAP.Error.NO_CREDENTIALS -> context.getString(R.string.error_no_credentials)
    CTAP.Error.PIN_INVALID -> context.getString(R.string.error_pin_incorrect)
    CTAP.Error.PIN_BLOCKED -> context.getString(R.string.error_pin_blocked)
    CTAP.Error.PIN_NOT_SET -> context.getString(R.string.error_pin_not_set)
    CTAP.Error.PIN_AUTH_INVALID -> context.getString(R.string.error_pin_auth_invalid)
    CTAP.Error.PIN_AUTH_BLOCKED -> context.getString(R.string.error_pin_auth_blocked)
    CTAP.Error.CREDENTIAL_EXCLUDED -> context.getString(R.string.error_credential_excluded)
    CTAP.Error.OPERATION_DENIED -> context.getString(R.string.error_operation_denied)
    CTAP.Error.USER_ACTION_TIMEOUT -> context.getString(R.string.error_user_action_timeout)
    CTAP.Error.TIMEOUT -> context.getString(R.string.error_timeout)
    CTAP.Error.KEY_STORE_FULL -> context.getString(R.string.error_key_store_full)
    CTAP.Error.UNSUPPORTED_ALGORITHM -> context.getString(R.string.error_unsupported_algorithm)
    CTAP.Error.KEEPALIVE_CANCEL -> context.getString(R.string.error_operation_cancelled)
    CTAP.Error.UV_BLOCKED -> context.getString(R.string.error_uv_blocked)
    CTAP.Error.UV_INVALID -> context.getString(R.string.error_uv_failed)
    else -> context.getString(R.string.error_ctap_unknown, this.name)
}
