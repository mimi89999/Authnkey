package pl.lebihan.authnkey

import android.content.Context
import android.content.pm.PackageManager
import android.nfc.NfcAdapter

/** Whether the device has NFC hardware at all. */
fun Context.hasNfc(): Boolean = NfcAdapter.getDefaultAdapter(this) != null

/** Whether NFC is present and switched on. Read at point of use; the user can toggle it anytime. */
fun Context.isNfcEnabled(): Boolean = NfcAdapter.getDefaultAdapter(this)?.isEnabled == true

/** Whether the device can act as a USB host (required to talk to a plugged-in key). */
fun Context.hasUsbHost(): Boolean =
    packageManager.hasSystemFeature(PackageManager.FEATURE_USB_HOST)

/** Whether to offer the "NFC is off" hint: hardware exists but is disabled. */
fun Context.shouldOfferNfcSettings(): Boolean = hasNfc() && !isNfcEnabled()

/**
 * The instruction to show while waiting for a key, covering only the transports
 * this device can actually use right now.
 */
fun Context.connectKeyInstruction(): String {
    val nfc = isNfcEnabled()
    val usb = hasUsbHost()
    return getString(
        when {
            nfc && usb -> R.string.instruction_connect_key
            nfc -> R.string.instruction_connect_key_nfc_only
            usb -> R.string.instruction_connect_key_usb_only
            else -> R.string.instruction_no_transport
        }
    )
}

/** USB permission denial message, only suggesting NFC when NFC is usable. */
fun Context.usbPermissionDeniedInstruction(): String = getString(
    if (isNfcEnabled()) R.string.instruction_usb_permission_denied
    else R.string.instruction_usb_permission_denied_no_nfc
)
