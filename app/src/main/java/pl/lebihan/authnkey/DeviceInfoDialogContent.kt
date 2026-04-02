package pl.lebihan.authnkey

import android.annotation.SuppressLint
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.view.ActionMode
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup

class DeviceInfoDialogContent(
    private val context: Context,
    private val deviceInfo: DeviceInfo
) {
    private val inflater: LayoutInflater = LayoutInflater.from(context)
    val view: View = inflater.inflate(R.layout.dialog_device_info, null)

    private val versionsChipGroup: ChipGroup = view.findViewById(R.id.versionsChipGroup)
    private val extensionsLabel: TextView = view.findViewById(R.id.extensionsLabel)
    private val extensionsChipGroup: ChipGroup = view.findViewById(R.id.extensionsChipGroup)
    private val aaguidLabel: TextView = view.findViewById(R.id.aaguidLabel)
    private val aaguidValue: TextView = view.findViewById(R.id.aaguidValue)
    private val optionsLabel: TextView = view.findViewById(R.id.optionsLabel)
    private val optionsContainer: LinearLayout = view.findViewById(R.id.optionsContainer)
    private val interfacesLabel: TextView = view.findViewById(R.id.interfacesLabel)
    private val interfacesChipGroup: ChipGroup = view.findViewById(R.id.interfacesChipGroup)
    private val algorithmsLabel: TextView = view.findViewById(R.id.algorithmsLabel)
    private val algorithmsChipGroup: ChipGroup = view.findViewById(R.id.algorithmsChipGroup)
    private val limitsLabel: TextView = view.findViewById(R.id.limitsLabel)
    private val limitsContainer: LinearLayout = view.findViewById(R.id.limitsContainer)

    private var activeActionMode: ActionMode? = null

    init {
        populateVersions()
        populateExtensions()
        populateAaguid()
        populateOptions()
        populateInterfaces()
        populateAlgorithms()
        populateLimits()
        setupOutsideTouchHandler()
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun setupOutsideTouchHandler() {
        view.setOnTouchListener { _, _ ->
            activeActionMode?.finish()
            false
        }
    }

    private fun populateVersions() {
        deviceInfo.versions.forEach { version ->
            versionsChipGroup.addView(createChip(version))
        }
    }

    private fun populateExtensions() {
        if (deviceInfo.extensions.isEmpty()) {
            extensionsLabel.visibility = View.GONE
            extensionsChipGroup.visibility = View.GONE
        } else {
            deviceInfo.extensions.forEach { extension ->
                extensionsChipGroup.addView(createChip(extension))
            }
        }
    }

    private fun populateAaguid() {
        val aaguid = deviceInfo.aaguid
        if (aaguid == null) {
            aaguidLabel.visibility = View.GONE
            aaguidValue.visibility = View.GONE
        } else {
            aaguidValue.text = formatAaguid(aaguid)
            aaguidValue.setOnLongClickListener { v ->
                activeActionMode = v.startActionMode(object : ActionMode.Callback {
                    override fun onCreateActionMode(mode: ActionMode, menu: Menu): Boolean {
                        mode.menuInflater.inflate(R.menu.menu_copy, menu)
                        return true
                    }

                    override fun onPrepareActionMode(mode: ActionMode, menu: Menu): Boolean = false

                    override fun onActionItemClicked(mode: ActionMode, item: MenuItem): Boolean {
                        return when (item.itemId) {
                            R.id.action_copy -> {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = ClipData.newPlainText("AAGUID", aaguidValue.text)
                                clipboard.setPrimaryClip(clip)
                                mode.finish()
                                true
                            }
                            else -> false
                        }
                    }

                    override fun onDestroyActionMode(mode: ActionMode) {
                        activeActionMode = null
                    }
                }, ActionMode.TYPE_FLOATING)
                true
            }
        }
    }

    private fun populateOptions() {
        if (deviceInfo.options.isEmpty()) {
            optionsLabel.visibility = View.GONE
            optionsContainer.visibility = View.GONE
        } else {
            deviceInfo.options.forEach { (key, value) ->
                addOptionRow(key, value)
            }
        }
    }

    private fun populateInterfaces() {
        if (deviceInfo.transports.isEmpty()) {
            interfacesLabel.visibility = View.GONE
            interfacesChipGroup.visibility = View.GONE
        } else {
            deviceInfo.transports.forEach { transport ->
                interfacesChipGroup.addView(createChip(transport.uppercase()))
            }
        }
    }

    private fun populateAlgorithms() {
        if (deviceInfo.algorithms.isEmpty()) {
            algorithmsLabel.visibility = View.GONE
            algorithmsChipGroup.visibility = View.GONE
        } else {
            deviceInfo.algorithms.forEach { alg ->
                alg.alg?.let { 
                    algorithmsChipGroup.addView(createChip(getAlgorithmName(it)))
                }
            }
        }
    }

    private fun populateLimits() {
        var hasLimits = false

        deviceInfo.maxMsgSize?.let {
            addLimitRow(R.string.device_info_limit_max_msg_size, it.toString())
            hasLimits = true
        }
        deviceInfo.maxCredentialCountInList?.let {
            addLimitRow(R.string.device_info_limit_max_creds_in_list, it.toString())
            hasLimits = true
        }
        deviceInfo.maxCredentialIdLength?.let {
            addLimitRow(R.string.device_info_limit_max_cred_id_length, it.toString())
            hasLimits = true
        }
        deviceInfo.minPinLength?.let {
            addLimitRow(R.string.device_info_limit_min_pin_length, it.toString())
            hasLimits = true
        }
        if (deviceInfo.pinUvAuthProtocols.isNotEmpty()) {
            addLimitRow(
                R.string.device_info_limit_pin_protocols,
                deviceInfo.pinUvAuthProtocols.joinToString(", ")
            )
            hasLimits = true
        }
        deviceInfo.firmwareVersion?.let {
            addLimitRow(R.string.device_info_limit_firmware, it.toString())
            hasLimits = true
        }

        if (!hasLimits) {
            limitsLabel.visibility = View.GONE
            limitsContainer.visibility = View.GONE
        }
    }

    private fun createChip(text: String): Chip {
        return Chip(context).apply {
            this.text = text
            isClickable = false
            isCheckable = false
        }
    }

    private fun addOptionRow(key: String, value: Boolean) {
        val row = inflater.inflate(R.layout.item_device_info_row, optionsContainer, false)
        row.findViewById<TextView>(R.id.labelText).text = getOptionName(key)
        row.findViewById<TextView>(R.id.valueText).text = if (value) context.getString(R.string.yes) else context.getString(R.string.no)
        optionsContainer.addView(row)
    }

    private fun addLimitRow(labelResId: Int, value: String) {
        val row = inflater.inflate(R.layout.item_device_info_row, limitsContainer, false)
        row.findViewById<TextView>(R.id.labelText).text = context.getString(labelResId)
        row.findViewById<TextView>(R.id.valueText).text = value
        limitsContainer.addView(row)
    }

    private fun getOptionName(key: String): String {
        val resId = when (key) {
            "rk" -> R.string.device_info_option_rk
            "up" -> R.string.device_info_option_up
            "uv" -> R.string.device_info_option_uv
            "plat" -> R.string.device_info_option_plat
            "clientPin" -> R.string.device_info_option_clientPin
            "credMgmt" -> R.string.device_info_option_credMgmt
            "credentialMgmtPreview" -> R.string.device_info_option_credentialMgmtPreview
            "largeBlobs" -> R.string.device_info_option_largeBlobs
            "pinUvAuthToken" -> R.string.device_info_option_pinUvAuthToken
            "authnrCfg" -> R.string.device_info_option_authnrCfg
            "uvAcfg" -> R.string.device_info_option_uvAcfg
            "setMinPINLength" -> R.string.device_info_option_setMinPINLength
            "makeCredUvNotRqd" -> R.string.device_info_option_makeCredUvNotRqd
            "alwaysUv" -> R.string.device_info_option_alwaysUv
            "ep" -> R.string.device_info_option_ep
            "bioEnroll" -> R.string.device_info_option_bioEnroll
            "uvBioEnroll" -> R.string.device_info_option_uvBioEnroll
            "userVerificationMgmtPreview" -> R.string.device_info_option_userVerificationMgmtPreview
            "noMcGaPermissionsWithClientPin" -> R.string.device_info_option_noMcGaPermissionsWithClientPin
            else -> return key
        }
        return context.getString(resId)
    }

    private fun getAlgorithmName(alg: Int): String {
        return when (alg) {
            -7 -> "ES256"
            -8 -> "EdDSA"
            -35 -> "ES384"
            -36 -> "ES512"
            -37 -> "PS256"
            -38 -> "PS384"
            -39 -> "PS512"
            -257 -> "RS256"
            -258 -> "RS384"
            -259 -> "RS512"
            else -> alg.toString()
        }
    }

    private fun formatAaguid(aaguid: ByteArray): String {
        if (aaguid.size != 16) return aaguid.joinToString("") { "%02x".format(it) }

        val hex = aaguid.joinToString("") { "%02x".format(it) }
        return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}"
    }
}
