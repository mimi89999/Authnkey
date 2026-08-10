package pl.lebihan.authnkey

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import com.google.android.material.dialog.MaterialAlertDialogBuilder

/**
 * Blocking progress overlay shown while credentials are enumerated off the key,
 * which can take a while on keys holding many of them.
 */
class CredentialProgressDialog(
    context: Context,
    initialStatus: String,
    showNfcHint: Boolean
) {
    private val view: View =
        LayoutInflater.from(context).inflate(R.layout.dialog_credential_progress, null)

    private val statusText: TextView = view.findViewById(R.id.progressStatus)
    private val detailText: TextView = view.findViewById(R.id.progressDetail)
    private val hintText: TextView = view.findViewById(R.id.progressHint)

    private val dialog: AlertDialog = MaterialAlertDialogBuilder(context)
        .setView(view)
        .setCancelable(false)
        .create()

    init {
        statusText.text = initialStatus
        hintText.visibility = if (showNfcHint) View.VISIBLE else View.GONE
    }

    fun show() {
        dialog.show()
    }

    fun update(status: String, detail: String? = null) {
        statusText.text = status
        detailText.text = detail.orEmpty()
        detailText.visibility = if (detail.isNullOrEmpty()) View.GONE else View.VISIBLE
    }

    fun dismiss() {
        dialog.dismiss()
    }
}
