package pl.lebihan.authnkey

import android.content.Context

/**
 * Centralized formatting for all UI output.
 * Keeps presentation logic separate from business logic.
 */
class OutputFormatter(private val context: Context) {

    // ========== Generic Status Formatting ==========

    /**
     * Format a header line
     */
    fun header(title: String): String = "=== $title ==="

    /**
     * Format a status message with header and body
     */
    fun status(title: String, message: String): String = """
        |${header(title)}
        |
        |$message
    """.trimMargin()

    /**
     * Format a list with header
     */
    fun list(title: String, items: List<String>): String = buildString {
        appendLine(header(title))
        appendLine()
        items.forEach { appendLine(it) }
    }

    /**
     * Format key-value pairs
     */
    fun keyValueList(title: String, pairs: List<Pair<String, String>>): String = buildString {
        appendLine(header(title))
        appendLine()
        pairs.forEach { (key, value) ->
            appendLine("$key: $value")
        }
    }

    // ========== Device Info Formatting ==========

    /**
     * Format device info error
     */
    fun formatDeviceInfoError(errorMessage: String): String =
        context.getString(R.string.device_info_error, errorMessage)

    // ========== Credential Management Formatting ==========

    /**
     * Complete credential report data
     */
    data class CredentialReport(
        val metadata: CredentialManagement.CredentialMetadata,
        val relyingParties: List<RelyingPartyWithCredentials>
    )

    data class RelyingPartyWithCredentials(
        val relyingParty: CredentialManagement.RelyingParty,
        val credentials: List<CredentialManagement.Credential>?,
        val error: String?
    )

    /**
     * Format a complete credential management report
     */
    fun formatCredentialReport(report: CredentialReport): String = buildString {
        appendLine(header(context.getString(R.string.credential_management_title)))
        appendLine()
        appendLine(context.getString(R.string.credential_stored_count, report.metadata.existingResidentCredentialsCount))
        appendLine(context.getString(R.string.credential_remaining_slots, report.metadata.maxPossibleRemainingCredentials))
        appendLine()

        if (report.metadata.existingResidentCredentialsCount == 0) {
            appendLine(context.getString(R.string.credential_no_credentials))
            return@buildString
        }

        if (report.relyingParties.isEmpty()) {
            appendLine(context.getString(R.string.credential_no_rps))
            return@buildString
        }

        appendLine(context.getString(R.string.credential_found_rps, report.relyingParties.size))
        appendLine()

        for ((index, rpWithCreds) in report.relyingParties.withIndex()) {
            append(formatRelyingParty(index, rpWithCreds))
        }

        appendLine(SEPARATOR)
    }

    /**
     * Format metadata section only (for partial display during loading)
     */
    fun formatMetadataSection(metadata: CredentialManagement.CredentialMetadata): String = buildString {
        appendLine(header(context.getString(R.string.credential_management_title)))
        appendLine()
        appendLine(context.getString(R.string.credential_stored_count, metadata.existingResidentCredentialsCount))
        appendLine(context.getString(R.string.credential_remaining_slots, metadata.maxPossibleRemainingCredentials))
        appendLine()
    }

    /**
     * Format empty credentials message
     */
    fun formatNoCredentials(metadata: CredentialManagement.CredentialMetadata): String = buildString {
        append(formatMetadataSection(metadata))
        appendLine(context.getString(R.string.credential_no_credentials))
    }

    /**
     * Format error when enumerating RPs
     */
    fun formatEnumerateRpsError(metadata: CredentialManagement.CredentialMetadata, errorMessage: String): String = buildString {
        append(formatMetadataSection(metadata))
        appendLine(context.getString(R.string.credential_error_enumerate_rps, errorMessage))
    }

    /**
     * Format no relying parties found
     */
    fun formatNoRelyingParties(metadata: CredentialManagement.CredentialMetadata): String = buildString {
        append(formatMetadataSection(metadata))
        appendLine(context.getString(R.string.credential_no_rps))
    }

    /**
     * Format a single relying party with its credentials
     */
    private fun formatRelyingParty(
        index: Int,
        rpWithCreds: RelyingPartyWithCredentials
    ): String = buildString {
        val rp = rpWithCreds.relyingParty

        appendLine(SEPARATOR)
        appendLine(context.getString(R.string.credential_rp_header, index + 1, rp.rpId ?: rp.rpIdHash.toHex()))
        rp.rpName?.let { appendLine(context.getString(R.string.credential_rp_name, it)) }
        appendLine()

        when {
            rpWithCreds.error != null -> {
                appendLine("  " + context.getString(R.string.credential_error_loading, rpWithCreds.error))
            }
            rpWithCreds.credentials != null -> {
                for ((credIndex, cred) in rpWithCreds.credentials.withIndex()) {
                    append(formatCredential(credIndex, cred))
                }
            }
        }
    }

    /**
     * Format a single credential
     */
    private fun formatCredential(index: Int, cred: CredentialManagement.Credential): String = buildString {
        appendLine("  " + context.getString(R.string.credential_number, index + 1))
        cred.userName?.let {
            appendLine("    " + context.getString(R.string.credential_username, it))
        }
        cred.userDisplayName?.let {
            appendLine("    " + context.getString(R.string.credential_display_name, it))
        }
        cred.userId?.let {
            appendLine("    " + context.getString(R.string.credential_user_id, it.toHex()))
        }
        appendLine("    " + context.getString(R.string.credential_id, cred.credentialId.toHex().take(32)))
        cred.credProtect?.let {
            appendLine("    " + context.getString(R.string.credential_protection, formatCredProtect(it)))
        }
        appendLine()
    }

    /**
     * Format credential protection level
     */
    private fun formatCredProtect(level: Int): String = when (level) {
        1 -> "userVerificationOptional"
        2 -> "userVerificationOptionalWithCredentialIDList"
        3 -> "userVerificationRequired"
        else -> "unknown ($level)"
    }

    // ========== PIN Change Formatting ==========

    /**
     * Format PIN change error message
     */
    fun formatPinChangeError(error: Throwable): String = when (error) {
        is PinProtocol.PinChangeError.InvalidPin -> status(
            context.getString(R.string.pin_invalid_title),
            context.getString(R.string.pin_invalid_message)
        )
        is PinProtocol.PinChangeError.PinBlocked -> status(
            context.getString(R.string.pin_blocked_title),
            context.getString(R.string.pin_blocked_message)
        )
        is PinProtocol.PinChangeError.PinPolicyViolation -> status(
            context.getString(R.string.pin_policy_violation_title),
            context.getString(R.string.pin_policy_violation_message)
        )
        is PinProtocol.PinChangeError.PinTooLong -> status(
            context.getString(R.string.pin_too_long_title),
            context.getString(R.string.pin_too_long_message)
        )
        is PinProtocol.PinChangeError.PinNotSet -> status(
            context.getString(R.string.pin_not_set_title),
            context.getString(R.string.pin_not_set_message)
        )
        is PinProtocol.PinChangeError.Other -> status(
            context.getString(R.string.pin_change_failed_title),
            context.getString(R.string.pin_change_failed_message, error.errorName)
        )
        else -> context.getString(R.string.error_generic, error.message ?: "Unknown error")
    }

    /**
     * Format PIN change success message
     */
    fun formatPinChangeSuccess(): String = status(
        context.getString(R.string.pin_change_success_title),
        context.getString(R.string.pin_change_success_message)
    )

    // ========== PIN Set Formatting ==========

    /**
     * Format PIN set error message
     */
    fun formatPinSetError(error: Throwable): String = when (error) {
        is PinProtocol.PinSetError.PinAlreadySet -> status(
            context.getString(R.string.pin_already_set_title),
            context.getString(R.string.pin_already_set_message)
        )
        is PinProtocol.PinSetError.PinPolicyViolation -> status(
            context.getString(R.string.pin_policy_violation_title),
            context.getString(R.string.pin_policy_violation_message)
        )
        is PinProtocol.PinSetError.PinTooLong -> status(
            context.getString(R.string.pin_too_long_title),
            context.getString(R.string.pin_too_long_message)
        )
        is PinProtocol.PinSetError.PinBlocked -> status(
            context.getString(R.string.pin_blocked_title),
            context.getString(R.string.pin_blocked_message)
        )
        is PinProtocol.PinSetError.Other -> status(
            context.getString(R.string.pin_set_failed_title),
            context.getString(R.string.pin_set_failed_message, error.errorName)
        )
        else -> context.getString(R.string.error_generic, error.message ?: "Unknown error")
    }

    /**
     * Format PIN set success message
     */
    fun formatPinSetSuccess(): String = status(
        context.getString(R.string.pin_set_success_title),
        context.getString(R.string.pin_set_success_message)
    )

    companion object {
        private const val SEPARATOR = "────────────────────────────────────────"
    }
}
