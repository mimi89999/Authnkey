package pl.lebihan.authnkey

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
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
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
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
        unregisterReceiver(usbPermissionReceiver)
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

                val isoDep = IsoDep.get(tag) ?: throw Exception("Not an ISO-DEP tag")
                val transport = NfcTransport(isoDep)

                if (!transport.selectFidoApplet()) {
                    throw Exception("Failed to select FIDO applet")
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
                statusText.text = getString(R.string.nfc_error, e.message ?: "")
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
                } ?: throw Exception("Failed to initialize FIDO communication")

                currentTransport = transport
                pinProtocol = PinProtocol(transport)
                credentialManagement = null

                updateConnectionStatus()
                statusText.text = getString(R.string.usb_connected)

            } catch (e: Exception) {
                statusText.text = getString(R.string.usb_error, e.message ?: "")
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

        reconnectDialog = AlertDialog.Builder(this)
            .setTitle(getString(R.string.connection_lost_title))
            .setMessage(getString(R.string.connection_lost_message))
            .setCancelable(false)
            .setNegativeButton(getString(R.string.cancel)) { _, _ ->
                awaitingNfcReconnect = false
                pendingAction = null
                resultText.text = getString(R.string.operation_cancelled)
                updateConnectionStatus()
            }
            .show()
    }

    private fun getDeviceInfo() {
        pendingAction = { getDeviceInfo() }

        scope.launch {
            try {
                val transport = currentTransport ?: throw Exception("No key connected")

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
                    resultText.text = outputFormatter.formatDeviceInfo(deviceInfo)
                } else {
                    resultText.text = outputFormatter.formatDeviceInfoError("Failed to parse response")
                }
                pendingAction = null

            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    showNfcReconnectDialog()
                } else {
                    resultText.text = getString(R.string.error_generic, e.message ?: "")
                    pendingAction = null
                    handleDisconnect()
                }
            }
        }
    }

    private fun listCredentials() {
        pendingAction = { listCredentials() }

        scope.launch {
            try {
                val transport = currentTransport ?: throw Exception("No key connected")

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

                val protocol = pinProtocol ?: throw Exception("PIN protocol not initialized")
                val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() }

                if (retries == null) {
                    resultText.text = getString(R.string.error_could_not_get_pin_status)
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
                    resultText.text = getString(R.string.error_generic, e.message ?: "")
                    pendingAction = null
                    handleDisconnect()
                }
            }
        }
    }

    private fun showPinDialogForCredentials(retries: Int, usePreviewCommand: Boolean) {
        val editText = EditText(this).apply {
            hint = getString(R.string.pin_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                    android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            setPadding(48, 32, 48, 32)
        }

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.pin_required_title))
            .setMessage(getString(R.string.pin_required_message, retries))
            .setView(editText)
            .setPositiveButton(getString(R.string.ok)) { _, _ ->
                val pin = editText.text.toString()
                if (pin.length >= 4) {
                    authenticateAndListCredentials(pin, usePreviewCommand)
                } else {
                    resultText.text = getString(R.string.error_pin_min_length)
                }
            }
            .setNegativeButton(getString(R.string.cancel), null)
            .show()
    }

    private fun authenticateAndListCredentials(pin: String, usePreviewCommand: Boolean) {
        // Save for potential reconnection
        pendingAction = { authenticateAndListCredentials(pin, usePreviewCommand) }

        scope.launch {
            try {
                val transport = currentTransport ?: throw Exception("No key connected")
                val protocol = pinProtocol ?: throw Exception("PIN protocol not initialized")

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
                   val authenticated = withContext(Dispatchers.IO) { protocol.getPinToken(pin) }
                if(!usePreviewCommand) {
                    val authenticated = withContext(Dispatchers.IO) { protocol.getPinToken(pin,4) }
                }
                if (!authenticated) {
                    if (isNfcDisconnected()) {
                        showNfcReconnectDialog()
                    } else {
                        resultText.text = getString(R.string.error_invalid_pin)
                        pendingAction = null
                    }
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
                        resultText.text = getString(R.string.error_metadata, it.message ?: "")
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
                        resultText.text = outputFormatter.formatEnumerateRpsError(metadata, it.message ?: "")
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
                                error = credsResult.exceptionOrNull()?.message
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

                // Format and display the complete report
                val report = OutputFormatter.CredentialReport(
                    metadata = metadata,
                    relyingParties = rpsWithCredentials
                )
                resultText.text = outputFormatter.formatCredentialReport(report)

                // Clear action after successful operation
                pendingAction = null

            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    showNfcReconnectDialog()
                } else {
                    resultText.text = getString(R.string.error_generic_with_trace, e.message ?: "", e.stackTraceToString())
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
                val protocol = pinProtocol ?: throw Exception("PIN protocol not initialized")

                resultText.text = getString(R.string.checking_pin_status)

                val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() }

                val dialogView = layoutInflater.inflate(R.layout.dialog_pin, null)
                val currentPinEdit = dialogView.findViewById<EditText>(R.id.currentPin)
                val newPinEdit = dialogView.findViewById<EditText>(R.id.newPin)
                val confirmPinEdit = dialogView.findViewById<EditText>(R.id.confirmPin)

                val message = if (retries != null) {
                    "PIN retries remaining: $retries"
                } else {
                    "Could not get PIN status"
                }

                pendingAction = null

                AlertDialog.Builder(this@MainActivity)
                    .setTitle(getString(R.string.change_pin_title))
                    .setMessage(message)
                    .setView(dialogView)
                    .setPositiveButton(getString(R.string.change)) { _, _ ->
                        val currentPin = currentPinEdit.text.toString()
                        val newPin = newPinEdit.text.toString()
                        val confirmPin = confirmPinEdit.text.toString()

                        if (newPin != confirmPin) {
                            resultText.text = getString(R.string.error_pins_dont_match)
                            return@setPositiveButton
                        }

                        if (newPin.length < 4) {
                            resultText.text = getString(R.string.error_pin_min_length)
                            return@setPositiveButton
                        }

                        changePin(currentPin, newPin)
                    }
                    .setNegativeButton(getString(R.string.cancel), null)
                    .show()

                resultText.text = ""

            } catch (e: Exception) {
                if (isNfcDisconnected()) {
                    showNfcReconnectDialog()
                } else {
                    resultText.text = getString(R.string.error_generic, e.message ?: "")
                    pendingAction = null
                    handleDisconnect()
                }
            }
        }
    }

    private fun changePin(currentPin: String, newPin: String) {
        pendingAction = { changePin(currentPin, newPin) }

        scope.launch {
            try {
                val protocol = pinProtocol ?: throw Exception("PIN protocol not initialized")

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
                    resultText.text = getString(R.string.error_generic, e.message ?: "")
                    pendingAction = null
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Check if credentials feature is supported
            if (!packageManager.hasSystemFeature(PackageManager.FEATURE_CREDENTIALS)) {
                providerStatusContainer.visibility = View.GONE
                return
            }

            providerStatusContainer.visibility = View.VISIBLE

            try {
                val credentialManager = getSystemService(android.credentials.CredentialManager::class.java)
                val componentName = ComponentName(this, AuthnkeyCredentialService::class.java)
                val isEnabled = credentialManager?.isEnabledCredentialProviderService(componentName) ?: false

                if (isEnabled) {
                    providerStatusContainer.setBackgroundColor(getColor(R.color.provider_enabled_background))
                    providerStatusText.setTextColor(getColor(R.color.provider_enabled_text))
                    providerStatusText.text = getString(R.string.provider_enabled)
                    btnEnableProvider.visibility = View.GONE
                } else {
                    providerStatusContainer.setBackgroundColor(getColor(R.color.provider_not_enabled_background))
                    providerStatusText.setTextColor(getColor(R.color.provider_not_enabled_text))
                    providerStatusText.text = getString(R.string.provider_not_enabled)
                    btnEnableProvider.visibility = View.VISIBLE
                }
            } catch (e: Exception) {
                providerStatusContainer.visibility = View.GONE
            }
        } else {
            providerStatusContainer.visibility = View.GONE
        }
    }

    private fun openProviderSettings() {
        val intent = Intent(Settings.ACTION_CREDENTIAL_PROVIDER)
            .setData(android.net.Uri.parse("package:$packageName"))
        startActivity(intent)
    }

    companion object {
        private const val ACTION_USB_PERMISSION = "pl.lebihan.authnkey.USB_PERMISSION"
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
