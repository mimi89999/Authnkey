package pl.lebihan.authnkey

import android.animation.ObjectAnimator
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.*

class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private lateinit var usbManager: UsbManager

    private lateinit var statusText: TextView
    private lateinit var connectionType: TextView
    private lateinit var resultText: TextView
    private lateinit var btnScanUsb: Button
    private lateinit var btnDeviceInfo: Button
    private lateinit var btnListCredentials: Button
    private lateinit var btnChangePin: Button
    private lateinit var providerStatusContainer: LinearLayout
    private lateinit var providerStatusText: TextView
    private lateinit var btnEnableProvider: Button

    private var currentTransport: FidoTransport? = null
    private var pinProtocol: PinProtocol? = null
    private var credentialManagement: CredentialManagement? = null
    private lateinit var outputFormatter: OutputFormatter

    // NFC reconnection state
    private var pendingAction: (() -> Unit)? = null
    private var awaitingNfcReconnect: Boolean = false
    private var reconnectDialog: AlertDialog? = null

    // Credentials dialog state
    private var credentialsDialog: AlertDialog? = null
    private var credentialsContent: CredentialsDialogContent? = null

    private var usbPermissionRequested = false

    private val scope = CoroutineScope(Dispatchers.Main + Job())

    private val usbPermissionReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == ACTION_USB_PERMISSION) {
                val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                }
                val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)

                if (granted && device != null) {
                    connectToUsbDevice(device)
                } else {
                    statusText.text = getString(R.string.usb_permission_denied)
                }
            }
        }
    }

    private val usbAttachReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == UsbManager.ACTION_USB_DEVICE_ATTACHED) {
                usbPermissionRequested = false

                val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                }

                if (device != null && UsbTransport.isFidoDevice(device) && currentTransport == null) {
                    if (usbManager.hasPermission(device)) {
                        connectToUsbDevice(device)
                    } else {
                        requestUsbPermission(device)
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        connectionType = findViewById(R.id.connectionType)
        resultText = findViewById(R.id.resultText)
        btnScanUsb = findViewById(R.id.btnScanUsb)
        btnDeviceInfo = findViewById(R.id.btnDeviceInfo)
        btnListCredentials = findViewById(R.id.btnListCredentials)
        btnChangePin = findViewById(R.id.btnChangePin)
        providerStatusContainer = findViewById(R.id.providerStatusContainer)
        providerStatusText = findViewById(R.id.providerStatusText)
        btnEnableProvider = findViewById(R.id.btnEnableProvider)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        usbManager = getSystemService(Context.USB_SERVICE) as UsbManager
        outputFormatter = OutputFormatter(this)

        // Register USB permission receiver
        val filter = IntentFilter(ACTION_USB_PERMISSION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(usbPermissionReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(usbPermissionReceiver, filter)
        }

        btnScanUsb.setOnClickListener { scanForUsbDevices() }
        btnDeviceInfo.setOnClickListener { getDeviceInfo() }
        btnListCredentials.setOnClickListener { listCredentials() }
        btnChangePin.setOnClickListener { showChangePinDialog() }
        btnEnableProvider.setOnClickListener { openProviderSettings() }

        updateConnectionStatus()
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(usbPermissionReceiver)
        } catch (e: Exception) {
            // Ignore
        }
        try {
            unregisterReceiver(usbAttachReceiver)
        } catch (e: Exception) {
            // Ignore
        }
        scope.cancel()
    }

    override fun onResume() {
        super.onResume()

        // Check credential provider status
        checkProviderStatus()

        // Enable NFC foreground dispatch
        nfcAdapter?.let { adapter ->
            val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            val pendingIntent = PendingIntent.getActivity(
                this, 0, intent,
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            val filters = arrayOf(IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED))
            val techLists = arrayOf(arrayOf(IsoDep::class.java.name))
            adapter.enableForegroundDispatch(this, pendingIntent, filters, techLists)
        }

        // Register USB attach receiver
        val usbAttachFilter = IntentFilter(UsbManager.ACTION_USB_DEVICE_ATTACHED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(usbAttachReceiver, usbAttachFilter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(usbAttachReceiver, usbAttachFilter)
        }

        // Auto-connect to already-plugged USB FIDO devices
        checkForUsbDevice()

        // Check if started by USB device attachment
        if (intent.action == UsbManager.ACTION_USB_DEVICE_ATTACHED) {
            val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
            }
            device?.let { handleUsbDevice(it) }
        }
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
        try {
            unregisterReceiver(usbAttachReceiver)
        } catch (e: Exception) {
            // Ignore
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        when (intent.action) {
            NfcAdapter.ACTION_TECH_DISCOVERED -> {
                val tag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
                }
                tag?.let { handleNfcTag(it) }
            }
            UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                }
                device?.let { handleUsbDevice(it) }
            }
        }
    }

    private fun handleNfcTag(tag: Tag) {
        scope.launch {
            try {
                // Close old transport (NFC tags can't be reused after moving away)
                currentTransport?.close()
                currentTransport = null

                val isoDep = IsoDep.get(tag) ?: throw AuthnkeyError.NotIsoDepTag()
                val transport = NfcTransport(isoDep)

                if (!transport.selectFidoApplet()) {
                    throw AuthnkeyError.FidoAppletNotFound()
                }

                currentTransport = transport
                pinProtocol = PinProtocol(transport)
                credentialManagement = null

                updateConnectionStatus()

                // Check if we were waiting for reconnection
                if (awaitingNfcReconnect) {
                    reconnectDialog?.dismiss()
                    reconnectDialog = null
                    awaitingNfcReconnect = false

                    val action = pendingAction
                    if (action != null) {
                        action()
                    } else {
                        statusText.text = getString(R.string.nfc_connected)
                        resultText.text = ""
                    }
                } else {
                    statusText.text = getString(R.string.nfc_connected)
                }

            } catch (e: Exception) {
                statusText.text = getString(R.string.nfc_error, e.toUserMessage(this@MainActivity))
                updateConnectionStatus()
            }
        }
    }

    private fun handleUsbDevice(device: UsbDevice) {
        if (!UsbTransport.isFidoDevice(device)) {
            return
        }

        if (usbManager.hasPermission(device)) {
            connectToUsbDevice(device)
        } else {
            requestUsbPermission(device)
        }
    }

    private fun scanForUsbDevices() {
        val devices = usbManager.deviceList.values
            .filter { UsbTransport.isFidoDevice(it) }

        if (devices.isEmpty()) {
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.no_devices_title))
                .setMessage(getString(R.string.no_devices_message))
                .setPositiveButton(getString(R.string.ok), null)
                .show()
            return
        }

        if (devices.size == 1) {
            handleUsbDevice(devices.first())
            return
        }

        // Show device selection dialog
        showDeviceSelectionDialog(devices)
    }

    /**
     * Check for already-plugged USB FIDO devices and connect if found.
     * Only connects if there's exactly one device and we're not already connected.
     */
    private fun checkForUsbDevice() {
        // Skip if already connected
        if (currentTransport?.isConnected == true) {
            return
        }

        val devices = usbManager.deviceList.values
            .filter { UsbTransport.isFidoDevice(it) }

        // Only auto-connect if exactly one FIDO device is found
        if (devices.size == 1) {
            val device = devices.first()
            if (usbManager.hasPermission(device)) {
                connectToUsbDevice(device)
            } else if (!usbPermissionRequested) {
                requestUsbPermission(device)
            }
        }
    }

    private fun showDeviceSelectionDialog(devices: Collection<UsbDevice>) {
        val dialogView = layoutInflater.inflate(R.layout.dialog_usb_devices, null)
        val recyclerView = dialogView.findViewById<RecyclerView>(R.id.deviceList)

        val dialog = AlertDialog.Builder(this)
            .setTitle(getString(R.string.select_security_key))
            .setView(dialogView)
            .setNegativeButton(getString(R.string.cancel), null)
            .create()

        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = UsbDeviceAdapter(devices.toList()) { device ->
            dialog.dismiss()
            handleUsbDevice(device)
        }

        dialog.show()
    }

    private fun requestUsbPermission(device: UsbDevice) {
        usbPermissionRequested = true

        val intent = Intent(ACTION_USB_PERMISSION).apply {
            setPackage(packageName)
        }
        val permissionIntent = PendingIntent.getBroadcast(
            this, 0,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        usbManager.requestPermission(device, permissionIntent)
    }

    private fun connectToUsbDevice(device: UsbDevice) {
        scope.launch {
            try {
                currentTransport?.close()
                currentTransport = null
                pinProtocol = null
                credentialManagement = null

                statusText.text = getString(R.string.connecting_usb)

                val transport = withContext(Dispatchers.IO) {
                    UsbTransport.create(usbManager, device)
                } ?: throw AuthnkeyError.ConnectionFailed()

                currentTransport = transport
                pinProtocol = PinProtocol(transport)
                credentialManagement = null

                updateConnectionStatus()
                statusText.text = getString(R.string.usb_connected)

            } catch (e: Exception) {
                statusText.text = getString(R.string.usb_error, e.toUserMessage(this@MainActivity))
                updateConnectionStatus()
            }
        }
    }

    private fun updateConnectionStatus() {
        val transport = currentTransport
        val connected = transport?.isConnected == true

        connectionType.text = if (connected) {
            getString(R.string.connected_via, transport?.transportType?.name ?: "")
        } else {
            getString(R.string.not_connected)
        }

        btnDeviceInfo.isEnabled = connected
        btnListCredentials.isEnabled = connected
        btnChangePin.isEnabled = connected

        // Update status text if not connected and not waiting for reconnect
        if (!connected && !awaitingNfcReconnect) {
            statusText.text = getString(R.string.waiting_for_key)
        }
    }

    private fun isNfcDisconnected(): Boolean {
        return currentTransport is NfcTransport && currentTransport?.isConnected == false
    }

    private fun showNfcReconnectDialog() {
        awaitingNfcReconnect = true
        statusText.text = getString(R.string.connection_lost)
        resultText.text = getString(R.string.waiting_reconnection)

        val dialogView = layoutInflater.inflate(R.layout.dialog_connection_lost, null)
        val iconBackground = dialogView.findViewById<View>(R.id.iconBackground)

        iconBackground.backgroundTintList = ColorStateList.valueOf(
            ContextCompat.getColor(this, R.color.warning_container)
        )

        val pulseAnimator = ObjectAnimator.ofFloat(iconBackground, View.ALPHA, 1f, 0.3f).apply {
            duration = 750
            repeatCount = ObjectAnimator.INFINITE
            repeatMode = ObjectAnimator.REVERSE
            interpolator = AccelerateDecelerateInterpolator()
            start()
        }

        reconnectDialog = MaterialAlertDialogBuilder(this)
            .setView(dialogView)
            .setCancelable(false)
            .setNegativeButton(getString(R.string.cancel)) { _, _ ->
                awaitingNfcReconnect = false
                pendingAction = null
                resultText.text = getString(R.string.operation_cancelled)
                updateConnectionStatus()
            }
            .setOnDismissListener { pulseAnimator.cancel() }
            .create()

        reconnectDialog?.show()
    }

    private fun getDeviceInfo() {
        pendingAction = { getDeviceInfo() }

        scope.launch {
            try {
                val transport = currentTransport ?: throw AuthnkeyError.NotConnected()

                resultText.text = getString(R.string.reading_device_info)

                val response = withContext(Dispatchers.IO) {
                    transport.sendCtapCommand(CTAP.buildCommand(CTAP.CMD_GET_INFO))
                }

                val error = CTAP.getResponseError(response)
                if (error != null) {
                    resultText.text = outputFormatter.formatDeviceInfoError(error.name)
                    pendingAction = null
                    return@launch
                }

                val deviceInfo = CTAP.parseGetInfoStructured(response)
                if (deviceInfo != null) {
                    resultText.text = ""
                    showDeviceInfoDialog(deviceInfo)
                } else {
                    resultText.text = outputFormatter.formatDeviceInfoError("Failed to parse response")
                }
                pendingAction = null

            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    showNfcReconnectDialog()
                } else {
                    resultText.text = e.toUserMessage(this@MainActivity)
                    pendingAction = null
                    handleDisconnect()
                }
            }
        }
    }

    private fun showDeviceInfoDialog(deviceInfo: DeviceInfo) {
        val content = DeviceInfoDialogContent(this, deviceInfo)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.device_info_dialog_title)
            .setView(content.view)
            .setPositiveButton(R.string.close, null)
            .show()
    }

    private fun listCredentials() {
        pendingAction = { listCredentials() }

        scope.launch {
            try {
                val transport = currentTransport ?: throw AuthnkeyError.NotConnected()

                resultText.text = getString(R.string.checking_cred_mgmt)

                val infoResponse = withContext(Dispatchers.IO) {
                    transport.sendCtapCommand(CTAP.buildCommand(CTAP.CMD_GET_INFO))
                }

                val deviceInfo = CTAP.parseGetInfoStructured(infoResponse)
                if (deviceInfo == null) {
                    resultText.text = getString(R.string.error_parse_device_info)
                    pendingAction = null
                    return@launch
                }

                if (!deviceInfo.supportsCredMgmt && !deviceInfo.supportsCredMgmtPreview) {
                    resultText.text = outputFormatter.status(
                        getString(R.string.credential_management_title),
                        "✗ " + getString(R.string.credential_management_not_supported)
                    )
                    pendingAction = null
                    return@launch
                }

                val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()
                val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() }.getOrElse { e ->
                    if (e is java.io.IOException) throw e
                    resultText.text = e.toUserMessage(this@MainActivity)
                    pendingAction = null
                    return@launch
                }

                if (retries == 0) {
                    resultText.text = getString(R.string.error_pin_blocked)
                    pendingAction = null
                    return@launch
                }

                // Clear pendingAction before showing dialog (will be set again with PIN)
                pendingAction = null
                showPinDialogForCredentials(retries, deviceInfo.usePreviewCommand)

            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    showNfcReconnectDialog()
                } else {
                    resultText.text = e.toUserMessage(this@MainActivity)
                    pendingAction = null
                    handleDisconnect()
                }
            }
        }
    }

    private fun showPinDialogForCredentials(retries: Int, usePreviewCommand: Boolean) {
        val dialogView = layoutInflater.inflate(R.layout.dialog_pin_entry, null)
        val pinInputField = dialogView.findViewById<PinInputField>(R.id.pinInputField)

        pinInputField.useNumericKeyboard = getKeyboardPreference()
        pinInputField.onKeyboardModeChanged = { saveKeyboardPreference(it) }

        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.pin_required_title))
            .setMessage(getString(R.string.pin_required_message, retries))
            .setView(dialogView)
            .setPositiveButton(getString(R.string.ok), null)
            .setNegativeButton(getString(R.string.cancel), null)
            .create()

        dialog.setOnShowListener {
            pinInputField.requestFocus()
            dialog.window?.let { window ->
                WindowCompat.getInsetsController(window, pinInputField).show(WindowInsetsCompat.Type.ime())
            }
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                pinInputField.validateAndGetPin()?.let { pin ->
                    dialog.dismiss()
                    authenticateAndListCredentials(pin, usePreviewCommand)
                }
            }
        }

        dialog.show()
        resultText.text = ""
    }

    private fun authenticateAndListCredentials(pin: String, usePreviewCommand: Boolean) {
        // Save for potential reconnection
        pendingAction = { authenticateAndListCredentials(pin, usePreviewCommand) }

        scope.launch {
            try {
                val transport = currentTransport ?: throw AuthnkeyError.NotConnected()
                val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()

                resultText.text = getString(R.string.authenticating)

                val initialized = withContext(Dispatchers.IO) { protocol.initialize() }
                if (!initialized) {
                    if (isNfcDisconnected()) {
                        showNfcReconnectDialog()
                    } else {
                        resultText.text = getString(R.string.error_init_pin_protocol)
                        pendingAction = null
                    }
                    return@launch
                }

                resultText.text = getString(R.string.verifying_pin)
                withContext(Dispatchers.IO) {
                    if (usePreviewCommand) protocol.requestPinToken(pin)
                    else protocol.requestPinToken(pin, PinProtocol.PERMISSION_CM)
                }.onFailure { e ->
                    if (e is java.io.IOException) throw e
                    resultText.text = e.toUserMessage(this@MainActivity)
                    pendingAction = null
                    return@launch
                }

                val credMgmt = CredentialManagement(transport, protocol, usePreviewCommand)
                credentialManagement = credMgmt

                resultText.text = getString(R.string.getting_metadata)
                val metadataResult = withContext(Dispatchers.IO) { credMgmt.getCredentialsMetadata() }

                val metadata = metadataResult.getOrElse {
                    if (isNfcDisconnected()) {
                        showNfcReconnectDialog()
                    } else {
                        resultText.text = getString(R.string.error_metadata, it.toUserMessage(this@MainActivity))
                        pendingAction = null
                    }
                    return@launch
                }

                // Show metadata while loading
                resultText.text = outputFormatter.formatMetadataSection(metadata)

                if (metadata.existingResidentCredentialsCount == 0) {
                    resultText.text = outputFormatter.formatNoCredentials(metadata)
                    pendingAction = null
                    return@launch
                }

                resultText.text = getString(R.string.enumerating_rps)
                val rpsResult = withContext(Dispatchers.IO) { credMgmt.enumerateRelyingParties() }

                val relyingParties = rpsResult.getOrElse {
                    if (isNfcDisconnected()) {
                        showNfcReconnectDialog()
                    } else {
                        resultText.text = outputFormatter.formatEnumerateRpsError(metadata, it.toUserMessage(this@MainActivity))
                        pendingAction = null
                    }
                    return@launch
                }

                if (relyingParties.isEmpty()) {
                    resultText.text = outputFormatter.formatNoRelyingParties(metadata)
                    pendingAction = null
                    return@launch
                }

                // Collect credentials for each RP
                val rpsWithCredentials = mutableListOf<OutputFormatter.RelyingPartyWithCredentials>()

                for (rp in relyingParties) {
                    resultText.text = getString(R.string.loading_credentials_for, rp.rpId ?: "RP")

                    val credsResult = withContext(Dispatchers.IO) {
                        credMgmt.enumerateCredentials(rp.rpIdHash)
                    }

                    if (credsResult.isFailure) {
                        if (isNfcDisconnected()) {
                            showNfcReconnectDialog()
                            return@launch
                        }
                        rpsWithCredentials.add(
                            OutputFormatter.RelyingPartyWithCredentials(
                                relyingParty = rp,
                                credentials = null,
                                error = credsResult.exceptionOrNull()?.toUserMessage(this@MainActivity)
                            )
                        )
                    } else {
                        rpsWithCredentials.add(
                            OutputFormatter.RelyingPartyWithCredentials(
                                relyingParty = rp,
                                credentials = credsResult.getOrThrow(),
                                error = null
                            )
                        )
                    }
                }

                // Build flat list of credentials with their RP IDs
                val credentialItems = rpsWithCredentials.flatMap { rpWithCreds ->
                    rpWithCreds.credentials?.map { cred ->
                        CredentialItem(
                            rpId = rpWithCreds.relyingParty.rpId ?: rpWithCreds.relyingParty.rpIdHash.toHex(),
                            credential = cred
                        )
                    } ?: emptyList()
                }

                // Show credentials dialog
                showCredentialsDialog(metadata, credentialItems)
                resultText.text = ""

                // Clear action after successful operation
                pendingAction = null

            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    showNfcReconnectDialog()
                } else {
                    resultText.text = e.toUserMessage(this@MainActivity)
                    pendingAction = null
                    handleDisconnect()
                }
            }
        }
    }

    private fun showChangePinDialog() {
        pendingAction = { showChangePinDialog() }

        scope.launch {
            try {
                val transport = currentTransport ?: throw AuthnkeyError.NotConnected()
                val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()

                resultText.text = getString(R.string.checking_pin_status)

                // Get device info to check if PIN is set
                val infoResponse = withContext(Dispatchers.IO) {
                    transport.sendCtapCommand(CTAP.buildCommand(CTAP.CMD_GET_INFO))
                }
                val deviceInfo = CTAP.parseGetInfoStructured(infoResponse)
                val isPinSet = deviceInfo?.clientPinSet == true
                val minPinLength = deviceInfo?.minPinLength ?: 4

                val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() }.getOrNull()

                pendingAction = null

                if (isPinSet) {
                    showChangePinDialogInternal(minPinLength, retries)
                } else {
                    showSetPinDialogInternal(minPinLength)
                }

            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    showNfcReconnectDialog()
                } else {
                    resultText.text = e.toUserMessage(this@MainActivity)
                    pendingAction = null
                    handleDisconnect()
                }
            }
        }
    }

    private fun showSetPinDialogInternal(minPinLength: Int) {
        val dialogView = layoutInflater.inflate(R.layout.dialog_pin_set, null)
        val newPinField = dialogView.findViewById<PinInputField>(R.id.newPin)
        val confirmPinField = dialogView.findViewById<PinInputField>(R.id.confirmPin)

        val useNumeric = getKeyboardPreference()
        listOf(newPinField, confirmPinField).forEach { field ->
            field.useNumericKeyboard = useNumeric
            field.minPinLength = minPinLength
        }

        val dialog = MaterialAlertDialogBuilder(this@MainActivity)
            .setTitle(getString(R.string.set_pin_title))
            .setMessage(getString(R.string.no_pin_set_message))
            .setView(dialogView)
            .setPositiveButton(getString(R.string.set), null)
            .setNegativeButton(getString(R.string.cancel), null)
            .create()

        dialog.setOnShowListener {
            newPinField.requestFocus()
            dialog.window?.let { window ->
                WindowCompat.getInsetsController(window, newPinField).show(WindowInsetsCompat.Type.ime())
            }
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val newPin = newPinField.pin ?: ""
                val confirmPin = confirmPinField.pin ?: ""

                confirmPinField.error = null

                when {
                    newPin != confirmPin -> {
                        confirmPinField.error = getString(R.string.error_pins_dont_match)
                    }
                    !newPinField.validate() -> {
                        // error already set by validate()
                    }
                    else -> {
                        dialog.dismiss()
                        setPin(newPin)
                    }
                }
            }
        }

        dialog.show()
        resultText.text = ""
    }

    private fun showChangePinDialogInternal(minPinLength: Int, retries: Int?) {
        val dialogView = layoutInflater.inflate(R.layout.dialog_pin_change, null)
        val currentPinField = dialogView.findViewById<PinInputField>(R.id.currentPin)
        val newPinField = dialogView.findViewById<PinInputField>(R.id.newPin)
        val confirmPinField = dialogView.findViewById<PinInputField>(R.id.confirmPin)

        val useNumeric = getKeyboardPreference()
        listOf(currentPinField, newPinField, confirmPinField).forEach { field ->
            field.useNumericKeyboard = useNumeric
        }
        listOf(newPinField, confirmPinField).forEach { field ->
            field.minPinLength = minPinLength
        }

        val message = if (retries != null) {
            getString(R.string.pin_retries_status, retries)
        } else {
            getString(R.string.error_pin_status)
        }

        val dialog = MaterialAlertDialogBuilder(this@MainActivity)
            .setTitle(getString(R.string.change_pin_title))
            .setMessage(message)
            .setView(dialogView)
            .setPositiveButton(getString(R.string.change), null)
            .setNegativeButton(getString(R.string.cancel), null)
            .create()

        dialog.setOnShowListener {
            currentPinField.requestFocus()
            dialog.window?.let { window ->
                WindowCompat.getInsetsController(window, currentPinField).show(WindowInsetsCompat.Type.ime())
            }
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val currentPin = currentPinField.pin ?: ""
                val newPin = newPinField.pin ?: ""
                val confirmPin = confirmPinField.pin ?: ""

                confirmPinField.error = null

                when {
                    newPin != confirmPin -> {
                        confirmPinField.error = getString(R.string.error_pins_dont_match)
                    }
                    !newPinField.validate() -> {
                        // error already set by validate()
                    }
                    else -> {
                        dialog.dismiss()
                        changePin(currentPin, newPin)
                    }
                }
            }
        }

        dialog.show()
        resultText.text = ""
    }

    private fun setPin(newPin: String) {
        pendingAction = { setPin(newPin) }

        scope.launch {
            try {
                val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()

                resultText.text = getString(R.string.initializing_pin_protocol)

                val initialized = withContext(Dispatchers.IO) { protocol.initialize() }
                if (!initialized) {
                    if (isNfcDisconnected()) {
                        showNfcReconnectDialog()
                    } else {
                        resultText.text = getString(R.string.error_init_pin_protocol)
                        pendingAction = null
                    }
                    return@launch
                }

                resultText.text = getString(R.string.setting_pin)

                val result = withContext(Dispatchers.IO) {
                    protocol.setPin(newPin)
                }

                result.fold(
                    onSuccess = {
                        resultText.text = outputFormatter.formatPinSetSuccess()
                        pendingAction = null
                    },
                    onFailure = { error ->
                        if (isNfcDisconnected()) {
                            showNfcReconnectDialog()
                            return@launch
                        }

                        resultText.text = outputFormatter.formatPinSetError(error)
                        pendingAction = null
                    }
                )

            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    showNfcReconnectDialog()
                } else {
                    resultText.text = e.toUserMessage(this@MainActivity)
                    pendingAction = null
                }
            }
        }
    }

    private fun changePin(currentPin: String, newPin: String) {
        pendingAction = { changePin(currentPin, newPin) }

        scope.launch {
            try {
                val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()

                resultText.text = getString(R.string.initializing_pin_protocol)

                val initialized = withContext(Dispatchers.IO) { protocol.initialize() }
                if (!initialized) {
                    if (isNfcDisconnected()) {
                        showNfcReconnectDialog()
                    } else {
                        resultText.text = getString(R.string.error_init_pin_protocol)
                        pendingAction = null
                    }
                    return@launch
                }

                resultText.text = getString(R.string.changing_pin)

                val result = withContext(Dispatchers.IO) {
                    protocol.changePin(currentPin, newPin)
                }

                result.fold(
                    onSuccess = {
                        resultText.text = outputFormatter.formatPinChangeSuccess()
                        pendingAction = null
                    },
                    onFailure = { error ->
                        if (isNfcDisconnected()) {
                            showNfcReconnectDialog()
                            return@launch
                        }

                        resultText.text = outputFormatter.formatPinChangeError(error)
                        pendingAction = null
                    }
                )

            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    showNfcReconnectDialog()
                } else {
                    resultText.text = e.toUserMessage(this@MainActivity)
                    pendingAction = null
                }
            }
        }
    }

    private fun showCredentialsDialog(
        metadata: CredentialManagement.CredentialMetadata,
        credentials: List<CredentialItem>
    ) {
        credentialsDialog?.dismiss()

        val content = CredentialsDialogContent(
            context = this,
            credentials = credentials,
            initialRemaining = metadata.maxPossibleRemainingCredentials,
            onDelete = ::confirmDeleteCredential
        )
        credentialsContent = content

        credentialsDialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.credentials_dialog_title)
            .setView(content.view)
            .setPositiveButton(R.string.close, null)
            .setOnDismissListener {
                credentialsDialog = null
                credentialsContent = null
            }
            .create()
        credentialsDialog?.show()
    }

    private fun confirmDeleteCredential(item: CredentialItem) {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.credential_delete_confirm_title)
            .setMessage(getString(R.string.credential_delete_confirm_message, item.rpId))
            .setPositiveButton(R.string.delete) { _, _ -> deleteCredential(item) }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun deleteCredential(item: CredentialItem) {
        scope.launch {
            try {
                val credMgmt = credentialManagement
                    ?: throw AuthnkeyError.NotConnected()

                resultText.text = getString(R.string.instruction_verifying)

                val result = withContext(Dispatchers.IO) {
                    credMgmt.deleteCredential(item.credential.credentialId)
                }

                result.fold(
                    onSuccess = {
                        credentialsContent?.notifyDeleted(item)
                        resultText.text = getString(R.string.credential_deleted)
                    },
                    onFailure = { error ->
                        if (isNfcDisconnected()) {
                            credentialsDialog?.dismiss()
                            showNfcReconnectDialog()
                        } else {
                            resultText.text = getString(R.string.credential_delete_error, error.toUserMessage(this@MainActivity))
                        }
                    }
                )
            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    credentialsDialog?.dismiss()
                    showNfcReconnectDialog()
                } else {
                    resultText.text = getString(R.string.credential_delete_error, e.toUserMessage(this@MainActivity))
                }
            }
        }
    }

    private fun handleDisconnect() {
        currentTransport?.close()
        currentTransport = null
        pinProtocol = null
        credentialManagement = null
        updateConnectionStatus()
    }

    private fun checkProviderStatus() {
        providerStatusContainer.visibility = View.VISIBLE

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE ||
            !packageManager.hasSystemFeature(PackageManager.FEATURE_CREDENTIALS)) {
            providerStatusContainer.backgroundTintList = ColorStateList.valueOf(getColor(R.color.provider_not_supported_background))
            providerStatusText.setTextColor(getColor(R.color.provider_not_supported_text))
            providerStatusText.text = getString(R.string.provider_not_supported)
            btnEnableProvider.visibility = View.GONE
            return
        }

        try {
            val credentialManager = getSystemService(android.credentials.CredentialManager::class.java)
            val componentName = ComponentName(this, AuthnkeyCredentialService::class.java)
            val isEnabled = credentialManager?.isEnabledCredentialProviderService(componentName) ?: false

            if (isEnabled) {
                providerStatusContainer.backgroundTintList = ColorStateList.valueOf(getColor(R.color.provider_enabled_background))
                providerStatusText.setTextColor(getColor(R.color.provider_enabled_text))
                providerStatusText.text = getString(R.string.provider_enabled)
                btnEnableProvider.visibility = View.GONE
            } else {
                providerStatusContainer.backgroundTintList = ColorStateList.valueOf(getColor(R.color.provider_not_enabled_background))
                providerStatusText.setTextColor(getColor(R.color.provider_not_enabled_text))
                providerStatusText.text = getString(R.string.provider_not_enabled)
                btnEnableProvider.visibility = View.VISIBLE
            }
        } catch (e: Exception) {
            providerStatusContainer.visibility = View.GONE
            resultText.text = e.message
        }
    }

    private fun openProviderSettings() {
        val intent = Intent(Settings.ACTION_CREDENTIAL_PROVIDER)
            .setData(android.net.Uri.parse("package:$packageName"))
        startActivity(intent)
    }

    private fun getKeyboardPreference(): Boolean =
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .getBoolean(PREF_USE_NUMERIC_KEYBOARD, true)

    private fun saveKeyboardPreference(numeric: Boolean) {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .edit { putBoolean(PREF_USE_NUMERIC_KEYBOARD, numeric) }
    }

    companion object {
        private const val ACTION_USB_PERMISSION = "pl.lebihan.authnkey.USB_PERMISSION"
        private const val PREFS_NAME = "authnkey_prefs"
        private const val PREF_USE_NUMERIC_KEYBOARD = "use_numeric_keyboard"
    }
}

/**
 * RecyclerView adapter for USB device selection
 */
class UsbDeviceAdapter(
    private val devices: List<UsbDevice>,
    private val onSelect: (UsbDevice) -> Unit
) : RecyclerView.Adapter<UsbDeviceAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val name: TextView = view.findViewById(R.id.deviceName)
        val info: TextView = view.findViewById(R.id.deviceInfo)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_usb_device, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val device = devices[position]
        val context = holder.itemView.context
        holder.name.text = device.productName ?: context.getString(R.string.unknown_device)
        holder.info.text = context.getString(
            R.string.device_info_format,
            String.format("%04X", device.vendorId),
            String.format("%04X", device.productId)
        )
        holder.itemView.setOnClickListener { onSelect(device) }
    }

    override fun getItemCount() = devices.size
}
