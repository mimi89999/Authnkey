package pl.lebihan.authnkey

import android.app.ActivityOptions
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.provider.PendingIntentHandler
import kotlinx.coroutines.*
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import org.json.JSONObject
import java.security.MessageDigest

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialProviderActivity : AppCompatActivity() {

    private sealed class UvMode {
        /** No user verification requested. */
        object None : UvMode()
        /** Ask the authenticator to perform UV itself. */
        object BuiltIn : UvMode()
        /** UV via a pinUvAuth token. */
        class WithToken(val authToken: PinProtocol.Authenticated) : UvMode()
    }

    private data class ClientData(val json: String?, val hash: ByteArray)

    private var nfcAdapter: NfcAdapter? = null
    private var connectPromptVisible = false
    private lateinit var usbManager: UsbManager

    private var bottomSheet: CredentialBottomSheet? = null

    private var ctapSession: CtapSession? = null
    private var pinProtocol: PinProtocol? = null

    private lateinit var request: PasskeyRequest
    private var pendingPin: String? = null  // PIN entered before key connection

    private var deviceSupportsUv: Boolean = false

    private var usbPermissionRequested = false
    private val connectMutex = Mutex()

    private enum class ResidentKeyRequirement {
        REQUIRED,
        PREFERRED,
        DISCOURAGED;

        companion object {
            fun fromString(value: String?): ResidentKeyRequirement = when (value) {
                "required" -> REQUIRED
                "discouraged" -> DISCOURAGED
                else -> PREFERRED
            }
        }

        fun requiresResidentKey(): Boolean = this != DISCOURAGED
    }

    /** WebAuthn PRF extension input. */
    private sealed class PrfInput(extension: JSONObject) {
        private val eval = extension.optJSONObject("eval")

        val hasEval get() = eval != null

        /** Inputs from the "prf" extension. */
        class Prf(extension: JSONObject) : PrfInput(extension) {
            // SHA-256("WebAuthn PRF" || 0x00 || input)
            override fun hmacSecretSalt(input: ByteArray): ByteArray =
                MessageDigest.getInstance("SHA-256").run {
                    update("WebAuthn PRF".toByteArray(Charsets.UTF_8))
                    update(0x00.toByte())
                    digest(input)
                }
        }

        /**
         * Inputs from Android's synthetic "prfAlreadyHashed" extension, used for hybrid
         * requests. They are already hashed into hmac-secret salts.
         */
        class AlreadyHashed(extension: JSONObject) : PrfInput(extension) {
            override fun hmacSecretSalt(input: ByteArray): ByteArray = input.also {
                require(it.size == 32) { "prfAlreadyHashed input must be 32 bytes" }
            }
        }

        protected abstract fun hmacSecretSalt(input: ByteArray): ByteArray

        /** The hmac-secret salts for the eval inputs. */
        fun evalSalts(): Pair<ByteArray, ByteArray?> {
            checkNotNull(eval) { "PRF eval inputs are missing" }
            fun salt(name: String) = hmacSecretSalt(
                Base64.decode(eval.getString(name), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
            )
            return Pair(salt("first"), if (eval.has("second")) salt("second") else null)
        }
    }

    private fun JSONObject.prfInput(): PrfInput? {
        val prf = optJSONObject("prf")
        val prfAlreadyHashed = optJSONObject("prfAlreadyHashed")
        require(prf == null || prfAlreadyHashed == null) {
            "Both prf and prfAlreadyHashed extensions are present"
        }
        return when {
            prf != null -> PrfInput.Prf(prf)
            prfAlreadyHashed != null -> PrfInput.AlreadyHashed(prfAlreadyHashed)
            else -> null
        }
    }

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
                    setInstruction(usbPermissionDeniedInstruction())
                }
            }
        }
    }

    private val usbAttachReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
            }

            when (intent.action) {
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                    usbPermissionRequested = false
                    if (device == null || !UsbTransport.isFidoDevice(device)) return

                    if (usbManager.hasPermission(device)) {
                        connectToUsbDevice(device)
                    } else {
                        requestUsbPermission(device)
                    }
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val transport = ctapSession?.transport as? UsbTransport ?: return
                    if (device?.deviceId == transport.deviceId) {
                        handleUsbDetached()
                    }
                }
            }
        }
    }

    // Fires when NFC is toggled anywhere, including the quick settings shade.
    private val nfcStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != NfcAdapter.ACTION_ADAPTER_STATE_CHANGED) return
            when (intent.getIntExtra(NfcAdapter.EXTRA_ADAPTER_STATE, NfcAdapter.STATE_OFF)) {
                NfcAdapter.STATE_ON, NfcAdapter.STATE_OFF ->
                    if (connectPromptVisible) showConnectPrompt()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        usbManager = getSystemService(USB_SERVICE) as UsbManager

        // Register USB permission receiver
        val filter = IntentFilter(ACTION_USB_PERMISSION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(usbPermissionReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(usbPermissionReceiver, filter)
        }

        val createRequest = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val getRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        request = try {
            when {
                createRequest != null -> PasskeyRequest.from(createRequest)
                getRequest != null -> PasskeyRequest.from(getRequest)
                else -> throw IllegalArgumentException("No passkey request in the intent")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Invalid request", e)
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        showBottomSheet(
            getString(
                when (request) {
                    is PasskeyRequest.Create -> R.string.create_passkey
                    is PasskeyRequest.Get -> R.string.sign_in
                }
            )
        )

        // Check if PIN is likely required based on userVerification preference
        checkPinRequirement()
    }

    private fun showBottomSheet(status: String) {
        bottomSheet = CredentialBottomSheet.newInstance(status, connectKeyInstruction()).apply {
            onCancelClick = { cancelOperation() }
            onPinEntered = { pin -> handlePinEntered(pin) }
            onBiometricSelected = { handleBiometricSelected() }
            onNfcSettingsClick = { openNfcSettings() }
        }
        bottomSheet?.show(supportFragmentManager, CredentialBottomSheet.TAG)
        bottomSheet?.setState(CredentialBottomSheet.State.WAITING)
        connectPromptVisible = true
        bottomSheet?.showNfcHint(shouldOfferNfcSettings())
    }

    /**
     * Asks the user to present a key, naming only the transports this device can
     * currently use. Re-callable: the instruction depends on live NFC state.
     */
    private fun showConnectPrompt() {
        connectPromptVisible = true
        bottomSheet?.setInstruction(connectKeyInstruction())
        bottomSheet?.showNfcHint(shouldOfferNfcSettings())
    }

    private fun openNfcSettings() {
        try {
            startActivity(Intent(Settings.ACTION_NFC_SETTINGS))
        } catch (e: Exception) {
            Log.w(TAG, "No NFC settings activity", e)
        }
    }

    private fun handlePinEntered(pin: String) {
        if (ctapSession?.isConnected == true) {
            val json = request.json
            showProgress(true)
            setInstruction(getString(R.string.instruction_verifying))
            setState(CredentialBottomSheet.State.PROCESSING)
            bottomSheet?.showPinInput(false)
            authenticateAndExecute(pin, json)
        } else {
            pendingPin = pin
            showConnectPrompt()
            setState(CredentialBottomSheet.State.WAITING)
            bottomSheet?.showPinInput(false)
        }
    }

    private fun handleBiometricSelected() {
        if (ctapSession?.isConnected == true) {
            val json = request.json
            bottomSheet?.showBiometricWaiting()
            setInstruction(getString(R.string.instruction_waiting_biometric))
            showProgress(true)
            if (ctapSession?.deviceInfo?.supportsPinUvAuthToken == true) {
                authenticateWithUvAndExecute(json)
            } else {
                executeWithBuiltInUv(json)
            }
        } else {
            // Key not connected yet — show waiting state
            showConnectPrompt()
            setState(CredentialBottomSheet.State.WAITING)
        }
    }

    private fun setStatus(text: String) {
        bottomSheet?.setStatus(text)
    }

    private fun setInstruction(text: String) {
        connectPromptVisible = false
        bottomSheet?.setInstruction(text)
        bottomSheet?.showNfcHint(false)
    }

    private fun showProgress(show: Boolean) {
        bottomSheet?.showProgress(show)
    }

    private fun setState(state: CredentialBottomSheet.State) {
        bottomSheet?.setState(state)
    }

    private fun checkPinRequirement() {
        // For required/preferred, or discoverable flow, ask for PIN upfront to minimize NFC taps
        val isDiscoverable = (request as? PasskeyRequest.Get)?.isDiscoverable == true
        if (request.userVerification != UserVerification.DISCOURAGED || isDiscoverable) {
            showPinDialogFirst()
        }
        // If discouraged with allowCredentials, just wait for key connection
    }

    private fun showPinDialogFirst() {
        setInstruction(getString(R.string.instruction_enter_pin))
        setState(CredentialBottomSheet.State.PIN)
        bottomSheet?.showPinInput(true)
    }

    private fun showPinDialogWithBiometric(retries: Int, requestJson: JSONObject) {
        runOnUiThread {
            showProgress(false)
            bottomSheet?.hideAccounts()
            setInstruction(getString(R.string.pin_retries_remaining, retries))
            setState(CredentialBottomSheet.State.PIN)
            bottomSheet?.showPinInput(true)
            bottomSheet?.showBiometricOption(true)
        }
    }

    override fun onResume() {
        super.onResume()

        // NFC may have been toggled while we were backgrounded.
        if (connectPromptVisible) showConnectPrompt()

        // Also catch toggles that happen while we're in the foreground (e.g. the quick
        // settings shade, which does not pause us).
        registerReceiver(
            nfcStateReceiver,
            IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED)
        )

        nfcAdapter?.let { adapter ->
            val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)

            val pendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val options = ActivityOptions.makeBasic().apply {
                    pendingIntentCreatorBackgroundActivityStartMode =
                        ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED
                }
                PendingIntent.getActivity(
                    this, 0, intent,
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                    options.toBundle()
                )
            } else {
                PendingIntent.getActivity(
                    this, 0, intent,
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            }

            val filters = arrayOf(IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED))
            val techLists = arrayOf(arrayOf(IsoDep::class.java.name))
            adapter.enableForegroundDispatch(this, pendingIntent, filters, techLists)
        }

        val usbAttachFilter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(usbAttachReceiver, usbAttachFilter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(usbAttachReceiver, usbAttachFilter)
        }

        if (ctapSession?.isConnected != true || ctapSession?.transportType == TransportType.USB) {
            checkForUsbDevice()
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
        try {
            unregisterReceiver(nfcStateReceiver)
        } catch (e: Exception) {
            // Ignore
        }
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
        try {
            unregisterReceiver(nfcStateReceiver)
        } catch (e: Exception) {
            // Ignore
        }
        scope.cancel()
        ctapSession?.close()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        if (intent.action == NfcAdapter.ACTION_TECH_DISCOVERED) {
            val tag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
            }
            tag?.let { handleNfcTag(it) }
        }
    }

    private fun checkForUsbDevice() {
        // Verify the existing USB connection is still usable
        try {
            ctapSession?.let {
                if (it.transportType == TransportType.USB) {
                    it.reclaimConnection()
                    return // still good
                }
            }
        } catch (e: AuthnkeyError.NotConnected) {
            ctapSession?.close()
            ctapSession = null
            pinProtocol = null
        }

        val devices = usbManager.deviceList.values.filter { UsbTransport.isFidoDevice(it) }
        if (devices.isNotEmpty()) {
            val device = devices.first()
            if (usbManager.hasPermission(device)) {
                connectToUsbDevice(device)
            } else if (!usbPermissionRequested) {
                requestUsbPermission(device)
            }
        }
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

    private fun handleNfcTag(tag: Tag) {
        scope.launch {
            try {
                ctapSession?.close()

                // Capture any valid PIN and hide input
                bottomSheet?.getCurrentPinIfValid()?.let { pendingPin = it }
                bottomSheet?.showPinInput(false)

                val transport = withContext(Dispatchers.IO) {
                    NfcTransport.connect(tag)
                }

                ctapSession = CtapSession.attach(transport)
                pinProtocol = PinProtocol(transport)

                setInstruction(getString(R.string.instruction_key_connected))
                setState(CredentialBottomSheet.State.PROCESSING)
                showProgress(true)

                processRequest()

            } catch (e: Exception) {
                ensureActive()
                Log.e(TAG, "NFC error", e)
                showProgress(false)
                if (e is android.nfc.TagLostException) {
                    setInstruction(getString(R.string.instruction_tag_lost))
                    setState(CredentialBottomSheet.State.TAG_LOST)
                } else {
                    setInstruction(getString(R.string.error_retry_format, e.toUserMessage(this@CredentialProviderActivity)))
                    setState(CredentialBottomSheet.State.ERROR)
                }
            }
        }
    }

    private fun connectToUsbDevice(device: UsbDevice) {
        scope.launch {
            if (!connectMutex.tryLock()) return@launch
            try {
                ctapSession?.close()

                // Capture any valid PIN and hide input
                bottomSheet?.getCurrentPinIfValid()?.let { pendingPin = it }
                bottomSheet?.showPinInput(false)

                setInstruction(getString(R.string.instruction_connecting_usb))
                setState(CredentialBottomSheet.State.PROCESSING)

                val transport = withContext(Dispatchers.IO) {
                    UsbTransport.connect(usbManager, device)
                }

                ctapSession = CtapSession.attach(transport)
                pinProtocol = PinProtocol(transport)

                setInstruction(getString(R.string.instruction_key_connected))
                showProgress(true)

                processRequest()

            } catch (e: Exception) {
                ensureActive()
                Log.e(TAG, "USB error", e)
                setInstruction(getString(R.string.error_retry_format, e.toUserMessage(this@CredentialProviderActivity)))
                setState(CredentialBottomSheet.State.ERROR)
                showProgress(false)
            } finally {
                connectMutex.unlock()
            }
        }
    }

    private fun processRequest() {
        scope.launch {
            try {
                val json = request.json
                val currentSession = ctapSession ?: throw AuthnkeyError.NotConnected()
                val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()

                // Check if clientPin is actually set on the device
                val deviceHasPin = currentSession.deviceInfo.clientPinSet
                val alwaysUv = currentSession.deviceInfo.options["alwaysUv"] == true
                deviceSupportsUv = currentSession.deviceInfo.supportsBuiltInUv
                val supportsPinUvAuthToken = currentSession.deviceInfo.supportsPinUvAuthToken
                val noMcGaWithClientPin = currentSession.deviceInfo.noMcGaPermissionsWithClientPin
                val canUsePinForMcGa = deviceHasPin && !noMcGaWithClientPin

                when {
                    // We already have PIN from pre-prompt
                    canUsePinForMcGa && pendingPin != null -> {
                        setInstruction(getString(R.string.instruction_authenticating))
                        authenticateAndExecute(pendingPin!!, json)
                    }
                    // Verification needed (required/preferred, or forced by alwaysUv)
                    request.userVerification != UserVerification.DISCOURAGED || alwaysUv -> when {
                        // Device has both usable PIN and built-in UV -> show PIN input with biometric option
                        canUsePinForMcGa && deviceSupportsUv -> {
                            val retries = withContext(Dispatchers.IO) {
                                protocol.getPinRetries()
                            }.getOrDefault(8)
                            showPinDialogWithBiometric(retries, json)
                        }
                        // Device has usable PIN only -> need to get PIN
                        canUsePinForMcGa -> {
                            val retries = withContext(Dispatchers.IO) {
                                protocol.getPinRetries()
                            }.getOrDefault(8)
                            showPinDialog(retries, json)
                        }
                        // Device supports built-in UV but PIN not usable
                        // -> go directly to biometric (use token flow if supported, otherwise built-in)
                        deviceSupportsUv -> {
                            if (supportsPinUvAuthToken) authenticateWithUvAndExecute(json)
                            else executeWithBuiltInUv(json)
                        }
                        // No verification method available
                        request.userVerification == UserVerification.REQUIRED || alwaysUv ->
                            throw if (noMcGaWithClientPin)
                                AuthnkeyError.PinNotSupportedForOperation()
                            else AuthnkeyError.UserVerificationRequiredNoPin()
                        else -> tryExecuteWithoutPin(json)
                    }
                    // UV discouraged, no alwaysUv -> try without
                    else -> tryExecuteWithoutPin(json)
                }

            } catch (e: Exception) {
                ensureActive()
                Log.e(TAG, "Error processing request", e)
                handleError(e)
            }
        }
    }

    private fun tryExecuteWithoutPin(json: JSONObject) {
        scope.launch {
            try {
                executeRequest(json, UvMode.None)
            } catch (e: CTAP.Exception) {
                // Check if authenticator requires PIN despite UV=discouraged
                if (e.error == CTAP.Error.PIN_REQUIRED ||
                    e.error == CTAP.Error.PIN_AUTH_INVALID) {
                    Log.d(TAG, "Authenticator requires PIN despite UV=discouraged")
                    val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()
                    val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() }.getOrDefault(8)
                    if (deviceSupportsUv) {
                        showPinDialogWithBiometric(retries, json)
                    } else {
                        showPinDialog(retries, json)
                    }
                } else {
                    Log.e(TAG, "Execute error", e)
                    handleError(e)
                }
            } catch (e: Exception) {
                ensureActive()
                Log.e(TAG, "Execute error", e)
                handleError(e)
            }
        }
    }

    private fun showPinDialog(retries: Int, requestJson: JSONObject) {
        runOnUiThread {
            showProgress(false)
            bottomSheet?.hideAccounts()
            setInstruction(getString(R.string.pin_retries_remaining, retries))
            setState(CredentialBottomSheet.State.PIN)
            bottomSheet?.showPinInput(true)
        }
    }

    private fun authenticateAndExecute(pin: String, requestJson: JSONObject) {
        scope.launch {
            try {
                val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()

                setInstruction(getString(R.string.instruction_initializing))
                val keyAgreement = withContext(Dispatchers.IO) {
                    protocol.initialize()
                }.getOrElse { throw AuthnkeyError.PinProtocolInitFailed() }

                val permissions = request.pinPermission
                val rpId = request.rpId

                setInstruction(getString(R.string.instruction_verifying_pin))
                val supportsPinUvAuthToken =
                    ctapSession?.deviceInfo?.supportsPinUvAuthToken == true
                val authToken = withContext(Dispatchers.IO) {
                    if (supportsPinUvAuthToken) {
                        keyAgreement.requestPinToken(pin, permissions, rpId)
                    } else {
                        keyAgreement.requestPinToken(pin)
                    }
                }.getOrElse { e ->
                    if (e is CTAP.Exception) {
                        pendingPin = null
                    }
                    if (e is CTAP.Exception && e.error == CTAP.Error.PIN_INVALID) {
                        val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() }.getOrThrow()
                        if (retries > 0) {
                            runOnUiThread {
                                showProgress(false)
                                setInstruction(getString(R.string.pin_incorrect_retries, retries))
                                setState(CredentialBottomSheet.State.PIN)
                                bottomSheet?.showPinInput(true)
                                // Re-show biometric option if device supports it
                                if (deviceSupportsUv) {
                                    bottomSheet?.showBiometricOption(true)
                                }
                            }
                        } else {
                            throw AuthnkeyError.PinBlocked()
                        }
                    } else {
                        throw e
                    }
                    return@launch
                }

                executeRequest(requestJson, UvMode.WithToken(authToken))

            } catch (e: Exception) {
                ensureActive()
                Log.e(TAG, "Authentication error", e)
                handleError(e)
            }
        }
    }

    /**
     * For CTAP2.0 authenticators that support built-in UV but not pinUvAuthToken.
     * Sets the "uv" option in the CTAP command and lets the authenticator handle
     * user verification internally (e.g., on-device fingerprint prompt).
     */
    private fun executeWithBuiltInUv(requestJson: JSONObject) {
        scope.launch {
            try {
                runOnUiThread {
                    bottomSheet?.showBiometricWaiting()
                    setInstruction(getString(R.string.instruction_waiting_biometric))
                    showProgress(true)
                }

                executeRequest(requestJson, UvMode.BuiltIn)

            } catch (e: Exception) {
                ensureActive()
                Log.e(TAG, "Built-in UV error", e)
                handleError(e)
            }
        }
    }

    /**
     * For CTAP2.1 authenticators that support pinUvAuthToken.
     * Obtains a UV token via the authenticator's built-in verification
     * (e.g., fingerprint) and uses it as a pinUvAuth parameter.
     */
    private fun authenticateWithUvAndExecute(requestJson: JSONObject) {
        scope.launch {
            try {
                val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()

                runOnUiThread {
                    bottomSheet?.showBiometricWaiting()
                    setInstruction(getString(R.string.instruction_waiting_biometric))
                    showProgress(true)
                }

                val keyAgreement = withContext(Dispatchers.IO) {
                    protocol.initialize()
                }.getOrElse { throw AuthnkeyError.PinProtocolInitFailed() }

                val permissions = request.pinPermission
                val rpId = request.rpId

                val authToken = withContext(Dispatchers.IO) {
                    keyAgreement.requestUvToken(permissions, rpId)
                }.getOrElse { e ->
                    if (e is CTAP.Exception) {
                        when (e.error) {
                            CTAP.Error.UV_INVALID -> {
                                // Biometric didn't match — let user retry or switch to PIN
                                Log.d(TAG, "UV_INVALID: biometric verification failed")
                                val uvRetries = withContext(Dispatchers.IO) {
                                    protocol.getUvRetries()
                                }.getOrDefault(0)

                                if (uvRetries > 0) {
                                    runOnUiThread {
                                        showProgress(false)
                                        setInstruction(getString(R.string.error_uv_invalid_retries, uvRetries))
                                        setState(CredentialBottomSheet.State.PIN)
                                        bottomSheet?.showPinInput(true)
                                        bottomSheet?.showBiometricOption(true)
                                    }
                                } else {
                                    // UV exhausted, fall back to PIN
                                    fallbackToPinAfterUvFailure(requestJson)
                                }
                                return@launch
                            }
                            CTAP.Error.UV_BLOCKED -> {
                                Log.d(TAG, "UV_BLOCKED: falling back to PIN")
                                fallbackToPinAfterUvFailure(requestJson)
                                return@launch
                            }
                            CTAP.Error.INVALID_SUBCOMMAND,
                            CTAP.Error.INVALID_COMMAND,
                            CTAP.Error.INVALID_PARAMETER -> {
                                // Authenticator doesn't actually support UV subcommand,
                                // fall back to PIN silently
                                Log.d(TAG, "UV subcommand not supported, falling back to PIN")
                                deviceSupportsUv = false
                                fallbackToPinAfterUvFailure(requestJson)
                                return@launch
                            }
                            CTAP.Error.OPERATION_DENIED -> {
                                // User denied on device (e.g. tapped cancel on the key)
                                runOnUiThread {
                                    showProgress(false)
                                    setInstruction(getString(R.string.error_operation_denied))
                                    setState(CredentialBottomSheet.State.PIN)
                                    bottomSheet?.showPinInput(true)
                                    if (deviceSupportsUv) {
                                        bottomSheet?.showBiometricOption(true)
                                    }
                                }
                                return@launch
                            }
                            else -> throw e
                        }
                    }
                    throw e
                }

                // UV succeeded — proceed with the request
                executeRequest(requestJson, UvMode.WithToken(authToken))

            } catch (e: Exception) {
                ensureActive()
                Log.e(TAG, "UV authentication error", e)
                handleError(e)
            }
        }
    }

    private suspend fun fallbackToPinAfterUvFailure(requestJson: JSONObject) {
        val deviceHasPin = ctapSession?.deviceInfo?.clientPinSet == true
        if (deviceHasPin) {
            val protocol = pinProtocol ?: throw AuthnkeyError.PinProtocolNotInitialized()
            val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() }.getOrDefault(8)
            runOnUiThread {
                showProgress(false)
                setInstruction(getString(R.string.error_uv_blocked))
                setState(CredentialBottomSheet.State.PIN)
                bottomSheet?.showPinInput(true)
                // Don't show biometric option since UV is blocked/unsupported
            }
        } else {
            throw AuthnkeyError.UvBlocked()
        }
    }

    private suspend fun executeRequest(requestJson: JSONObject, uvMode: UvMode) {
        val transport = ctapSession?.transport ?: throw AuthnkeyError.NotConnected()

        when (request) {
            is PasskeyRequest.Create -> executeCreateCredential(transport, requestJson, uvMode)
            is PasskeyRequest.Get -> executeGetAssertion(transport, requestJson, uvMode)
        }
    }

    private suspend fun executeCreateCredential(
        transport: FidoTransport,
        requestJson: JSONObject,
        uvMode: UvMode
    ) {
        setInstruction(getString(R.string.instruction_creating))

        // Parse request
        val rp = requestJson.getJSONObject("rp")
        val rpId = rp.getString("id")
        val rpName = rp.optString("name", rpId)

        val user = requestJson.getJSONObject("user")
        val userId = Base64.decode(user.getString("id"), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        val userName = user.optString("name", "")
        val userDisplayName = user.optString("displayName", userName)

        val challenge = Base64.decode(
            requestJson.getString("challenge"),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )

        val paramsArray = requestJson.getJSONArray("pubKeyCredParams")
        val pubKeyCredParams = List(paramsArray.length()) { i ->
            val param = paramsArray.getJSONObject(i)
            Pair(param.getString("type"), param.getInt("alg"))
        }

        // Parse excludeCredentials if present
        val excludeList = if (requestJson.has("excludeCredentials")) {
            val excludeArray = requestJson.getJSONArray("excludeCredentials")
            List(excludeArray.length()) { i ->
                val cred = excludeArray.getJSONObject(i)
                FidoCommands.CredentialDescriptor(
                    type = "public-key",
                    id = Base64.decode(
                        cred.getString("id"),
                        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                    ),
                    transports = cred.optJSONArray("transports")?.let { transports ->
                        List(transports.length()) { transports.optString(it) }
                            .filter(String::isNotEmpty)
                            .map(TransportType::of)
                            .toSet()
                    } ?: emptySet(),
                )
            }
        } else emptyList()

        // Parse authenticatorSelection for residentKey requirement
        val authSelection = requestJson.optJSONObject("authenticatorSelection")
        val residentKey = ResidentKeyRequirement.fromString(
            authSelection?.optString("residentKey", "preferred")
        )

        // Parse extensions
        val extensions = requestJson.optJSONObject("extensions")
        val credPropsRequested = extensions?.optBoolean("credProps", false) ?: false
        val prfRequested = extensions?.prfInput() != null

        // Check if authenticator supports hmac-secret (CTAP2 backing for PRF)
        val authenticatorSupportsHmacSecret = ctapSession?.deviceInfo?.extensions?.contains("hmac-secret") == true

        // Build CTAP extensions map
        val ctapExtensions = mutableMapOf<String, Any>()
        if (prfRequested && authenticatorSupportsHmacSecret) {
            ctapExtensions["hmac-secret"] = true
        }

        // Build clientDataJSON with proper origin
        val origin = computeOrigin()
        val clientData = request.clientDataHash.let { hash ->
            if (hash != null && origin.startsWith("https://")) {
                ClientData(null, hash)
            } else {
                val json = JSONObject().apply {
                    put("type", "webauthn.create")
                    put("challenge", requestJson.getString("challenge"))
                    put("origin", origin)
                    put("crossOrigin", false)
                }.toString().replace("\\/", "/") // Android JSONObject escapes slashes
                ClientData(json, FidoCommands.hashClientData(json))
            }
        }

        // Resolve UV mode
        val fidoUvMode = when (uvMode) {
            is UvMode.None -> FidoCommands.UvMode.None
            is UvMode.BuiltIn -> FidoCommands.UvMode.BuiltIn
            is UvMode.WithToken -> FidoCommands.UvMode.AuthToken(
                uvMode.authToken.computeAuthParam(clientData.hash),
                protocol = 1
            )
        }

        // Build and send command
        val command = FidoCommands.buildMakeCredential(
            clientDataHash = clientData.hash,
            rpId = rpId,
            rpName = rpName,
            userId = userId,
            userName = userName,
            userDisplayName = userDisplayName,
            pubKeyCredParams = pubKeyCredParams,
            excludeList = excludeList.ifEmpty { null },
            requireResidentKey = residentKey.requiresResidentKey(),
            uvMode = fidoUvMode,
            extensions = ctapExtensions.ifEmpty { null },
        )

        runOnUiThread {
            if (transport.transportType == TransportType.USB) {
                setInstruction(getString(R.string.instruction_touch_key))
                setState(CredentialBottomSheet.State.TOUCH)
            }
        }

        val response = withContext(Dispatchers.IO) {
            transport.sendCtapCommand(command)
        }

        val result = FidoCommands.parseMakeCredentialResponse(response)
        val makeCredResult = result.getOrElse { throw it }

        // Build attestation object (CBOR encoded)
        val attestationObject = buildAttestationObject(
            makeCredResult.fmt,
            makeCredResult.attStmt,
            makeCredResult.authData
        )

        // Parse authData structure
        val authData = AuthenticatorData.parse(makeCredResult.authData)
        val credentialId = authData?.attestedCredentialData?.credentialId ?: ByteArray(0)

        // Determine if credential is actually discoverable
        // If we requested rk AND the authenticator supports it AND succeeded, it's discoverable
        val supportsResidentKey = ctapSession?.deviceInfo?.options?.get("rk") ?: true
        val isDiscoverable = residentKey.requiresResidentKey() && supportsResidentKey

        // Check if hmac-secret was confirmed in the authenticator's authData extensions
        val hmacSecretEnabled = if (prfRequested && authenticatorSupportsHmacSecret) {
            // If the authenticator supports hmac-secret and we requested it,
            // check if the authData extensions confirm it
            val extData = authData?.extensions
            extData?.bool("hmac-secret") ?: true // null means it was accepted without explicit confirmation
        } else false

        // Transports the key advertises, including the one currently in use
        val transports = setOf(transport.transportType) +
            ctapSession?.deviceInfo?.transports.orEmpty()

        // Build response JSON
        val responseJson = JSONObject().apply {
            put("id", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("rawId", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("type", "public-key")
            put("authenticatorAttachment", "cross-platform")
            put("response", JSONObject().apply {
                clientData.json?.let {
                    put("clientDataJSON", Base64.encodeToString(
                        it.toByteArray(),
                        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                    ))
                }
                put("attestationObject", Base64.encodeToString(
                    attestationObject,
                    Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                ))
                put("transports", org.json.JSONArray(transports.map { it.value }))
                put("authenticatorData", Base64.encodeToString(
                    makeCredResult.authData,
                    Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                ))
                authData?.attestedCredentialData?.let { attCredData ->
                    attCredData.publicKeyAlgorithm?.let { alg ->
                        put("publicKeyAlgorithm", alg)
                    }
                    encodePublicKeySpki(attCredData)?.let { spki ->
                        put("publicKey", Base64.encodeToString(
                            spki,
                            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                        ))
                    }
                }
            })
            put("clientExtensionResults", JSONObject().apply {
                if (credPropsRequested) {
                    put("credProps", JSONObject().apply {
                        put("rk", isDiscoverable)
                    })
                }
                if (prfRequested) {
                    put("prf", JSONObject().apply {
                        put("enabled", hmacSecretEnabled)
                    })
                }
            })
        }

        returnResult(responseJson.toString())
    }

    private suspend fun executeGetAssertion(
        transport: FidoTransport,
        requestJson: JSONObject,
        uvMode: UvMode
    ) {
        setInstruction(getString(R.string.instruction_signing_in))

        // Parse request
        val rpId = requestJson.getString("rpId")
        val challenge = Base64.decode(
            requestJson.getString("challenge"),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )

        // Parse allowCredentials if present
        val allowList = if (requestJson.has("allowCredentials")) {
            val allowArray = requestJson.getJSONArray("allowCredentials")
            List(allowArray.length()) { i ->
                val cred = allowArray.getJSONObject(i)
                FidoCommands.CredentialDescriptor(
                    type = "public-key",
                    id = Base64.decode(
                        cred.getString("id"),
                        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                    ),
                    transports = cred.optJSONArray("transports")?.let { transports ->
                        List(transports.length()) { transports.optString(it) }
                            .filter(String::isNotEmpty)
                            .map(TransportType::of)
                            .toSet()
                    } ?: emptySet(),
                )
            }
        } else emptyList()

        // Parse PRF extension
        val extensions = requestJson.optJSONObject("extensions")
        val prfInput = extensions?.prfInput()
        val authenticatorSupportsHmacSecret = ctapSession?.deviceInfo?.extensions?.contains("hmac-secret") == true
        val prfRequested = prfInput?.hasEval == true

        // Prepare hmac-secret extension for getAssertion if PRF is requested
        var hmacSecretExtensions: CborRaw? = null
        var prfHasTwoSalts = false
        var prfKeyAgreement: PinProtocol.Initialized? = null

        if (prfRequested && authenticatorSupportsHmacSecret) {
            // Get Initialized state: from Authenticated if available, or fresh key agreement
            val initState = (uvMode as? UvMode.WithToken)?.authToken?.keyAgreement
            prfKeyAgreement = if (initState != null) {
                initState
            } else {
                val protocol = this.pinProtocol
                    ?: throw Exception("PIN protocol not available for PRF")
                withContext(Dispatchers.IO) {
                    protocol.initialize()
                }.getOrElse {
                    throw Exception("Failed to initialize key agreement for PRF")
                }
            }
            val prfState = prfKeyAgreement

            val (salt1, salt2) = prfInput.evalSalts()
            prfHasTwoSalts = salt2 != null

            // Build hmac-secret extension input
            val hmacInput = prfState.buildHmacSecretInput(salt1, salt2)

            // Build the CBOR extensions map: {"hmac-secret": {1: coseKey, 2: saltEnc, 3: saltAuth}}
            val coseKey = prfState.encodePlatformCoseKeyBytes()

            hmacSecretExtensions = cbor {
                map {
                    "hmac-secret" to map {
                        1 to coseKey
                        2 to bytes(hmacInput.saltEnc)
                        3 to bytes(hmacInput.saltAuth)
                    }
                }
            }.let { CborRaw(it.toList()) }
        }

        // Build clientDataJSON with proper origin
        val origin = computeOrigin()
        val clientData = request.clientDataHash.let { hash ->
            if (hash != null && origin.startsWith("https://")) {
                ClientData(null, hash)
            } else {
                val json = JSONObject().apply {
                    put("type", "webauthn.get")
                    put("challenge", requestJson.getString("challenge"))
                    put("origin", origin)
                    put("crossOrigin", false)
                }.toString().replace("\\/", "/") // Android JSONObject escapes slashes
                ClientData(json, FidoCommands.hashClientData(json))
            }
        }

        // Resolve UV mode
        val fidoUvMode = when (uvMode) {
            is UvMode.None -> FidoCommands.UvMode.None
            is UvMode.BuiltIn -> FidoCommands.UvMode.BuiltIn
            is UvMode.WithToken -> FidoCommands.UvMode.AuthToken(
                uvMode.authToken.computeAuthParam(clientData.hash),
                protocol = 1
            )
        }

        val maxCredentialCountInList =
            ctapSession?.deviceInfo?.maxCredentialCountInList ?: Int.MAX_VALUE

        val effectiveAllowList = if (allowList.size > maxCredentialCountInList) {
            allowList.filterNot { cred ->
                TransportType.INTERNAL in cred.transports &&
                        TransportType.USB !in cred.transports &&
                        TransportType.NFC !in cred.transports
            }.ifEmpty { allowList }
        } else allowList

        // Build and send command
        val command = FidoCommands.buildGetAssertion(
            rpId = rpId,
            clientDataHash = clientData.hash,
            allowList = effectiveAllowList.ifEmpty { null },
            uvMode = fidoUvMode,
            extensions = hmacSecretExtensions,
        )

        runOnUiThread {
            if (transport.transportType == TransportType.USB) {
                setInstruction(getString(R.string.instruction_touch_key))
                setState(CredentialBottomSheet.State.TOUCH)
            }
        }

        val response = withContext(Dispatchers.IO) {
            transport.sendCtapCommand(command)
        }

        val result = FidoCommands.parseGetAssertionResponse(response)
        val firstAssertion = result.getOrElse { throw it }

        // Check if there are multiple credentials
        val numCredentials = firstAssertion.numberOfCredentials ?: 1
        val selectedAssertion = if (numCredentials > 1) {
            // Collect all assertions while key is still connected
            val assertions = mutableListOf(firstAssertion)
            repeat(numCredentials - 1) {
                val nextResponse = withContext(Dispatchers.IO) {
                    transport.sendCtapCommand(FidoCommands.buildGetNextAssertion())
                }
                val nextResult = FidoCommands.parseGetAssertionResponse(nextResponse)
                nextResult.getOrNull()?.let { assertions.add(it) }
            }

            // Show picker and wait for selection
            showCredentialPicker(assertions)
        } else {
            firstAssertion
        }

        // Get credential ID from response or effectiveAllowList
        val credentialId = selectedAssertion.credential?.id
            ?: if (effectiveAllowList.isNotEmpty()) effectiveAllowList[0].id else ByteArray(0)

        // Parse PRF results from authenticator data extensions
        var prfResults: JSONObject? = null
        if (prfRequested && prfKeyAgreement != null) {
            val authData = AuthenticatorData.parse(selectedAssertion.authData)
            val hmacSecretOutput = authData?.extensions?.bytes("hmac-secret")

            if (hmacSecretOutput != null) {
                val decrypted = prfKeyAgreement.decryptHmacSecretOutput(hmacSecretOutput)
                if (decrypted != null) {
                    prfResults = JSONObject().apply {
                        val first = decrypted.sliceArray(0 until 32)
                        put("first", Base64.encodeToString(
                            first, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                        ))
                        if (prfHasTwoSalts && decrypted.size >= 64) {
                            val second = decrypted.sliceArray(32 until 64)
                            put("second", Base64.encodeToString(
                                second, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                            ))
                        }
                    }
                }
            }
        }

        // Build response JSON
        val responseJson = JSONObject().apply {
            put("id", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("rawId", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("type", "public-key")
            put("authenticatorAttachment", "cross-platform")
            put("response", JSONObject().apply {
                clientData.json?.let {
                    put("clientDataJSON", Base64.encodeToString(
                        it.toByteArray(),
                        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                    ))
                }
                put("authenticatorData", Base64.encodeToString(
                    selectedAssertion.authData,
                    Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                ))
                put("signature", Base64.encodeToString(
                    selectedAssertion.signature,
                    Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                ))
                selectedAssertion.user?.id?.let { userId ->
                    put("userHandle", Base64.encodeToString(
                        userId,
                        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                    ))
                }
            })
            put("clientExtensionResults", JSONObject().apply {
                if (prfResults != null) {
                    put("prf", JSONObject().apply {
                        put("results", prfResults)
                    })
                }
            })
        }

        returnResult(responseJson.toString())
    }

    private suspend fun showCredentialPicker(
        assertions: List<FidoCommands.GetAssertionResponse>
    ): FidoCommands.GetAssertionResponse {
        return suspendCancellableCoroutine { continuation ->
            runOnUiThread {
                val accounts = assertions.map { assertion ->
                    val displayName = assertion.user?.displayName
                        ?: assertion.user?.name
                        ?: getString(R.string.unknown_account)
                    val subtitle = if (assertion.user?.displayName != null && assertion.user.name != null) {
                        assertion.user.name
                    } else null
                    CredentialBottomSheet.AccountInfo(displayName, subtitle)
                }

                setStatus(getString(R.string.choose_account))
                setInstruction("")
                showProgress(false)

                bottomSheet?.onAccountSelected = { index ->
                    bottomSheet?.hideAccounts()
                    continuation.resume(assertions[index]) {}
                }
                bottomSheet?.showAccounts(accounts)
            }
        }
    }

    private fun buildAttestationObject(
        fmt: String,
        attStmt: Map<*, *>,
        authData: ByteArray
    ): ByteArray = cbor {
        map {
            "fmt" to fmt
            "attStmt" to attStmt
            "authData" to bytes(authData)
        }
    }

    private fun encodePublicKeySpki(attCredData: AttestedCredentialData): ByteArray? {
        val kty = attCredData.keyType ?: return null
        val crv = attCredData.curve ?: return null
        val coseKey = attCredData.credentialPublicKey

        return when (kty) {
            CTAP.COSE_KTY_EC2 -> encodeEc2KeyAsSpki(coseKey, crv)
            CTAP.COSE_KTY_OKP -> encodeOkpKeyAsSpki(coseKey, crv)
            else -> null
        }
    }

    private fun encodeEc2KeyAsSpki(coseKey: Map<*, *>, crv: Int): ByteArray? {
        if (crv != CTAP.COSE_CRV_P256) return null

        val x = coseKey[-2L] as? ByteArray ?: return null
        val y = coseKey[-3L] as? ByteArray ?: return null

        val point = byteArrayOf(0x04) + x + y
        val bitString = byteArrayOf(0x03, (point.size + 1).toByte(), 0x00) + point
        val content = EC2_P256_ALGORITHM_ID + bitString
        return byteArrayOf(0x30, content.size.toByte()) + content
    }

    private fun encodeOkpKeyAsSpki(coseKey: Map<*, *>, crv: Int): ByteArray? {
        if (crv != CTAP.COSE_CRV_ED25519) return null

        val x = coseKey[-2L] as? ByteArray ?: return null

        val bitString = byteArrayOf(0x03, (x.size + 1).toByte(), 0x00) + x
        val content = OKP_ED25519_ALGORITHM_ID + bitString
        return byteArrayOf(0x30, content.size.toByte()) + content
    }

    private fun returnResult(responseJson: String) {
        setResult(RESULT_OK, request.responseResult(responseJson))
        finish()
    }

    private fun handleUsbDetached() {
        ctapSession?.close()
        ctapSession = null
        pinProtocol = null
        pendingPin = null

        runOnUiThread {
            showProgress(false)
            bottomSheet?.showPinInput(false)
            setInstruction(getString(R.string.error_format, getString(R.string.error_key_disconnected)))
            setState(CredentialBottomSheet.State.ERROR)
        }
    }

    private fun handleError(e: Exception) {
        runOnUiThread {
            showProgress(false)
            if (e is android.nfc.TagLostException) {
                setInstruction(getString(R.string.instruction_tag_lost))
                setState(CredentialBottomSheet.State.TAG_LOST)
            } else {
                setInstruction(getString(R.string.error_format, e.toUserMessage(this)))
                setState(CredentialBottomSheet.State.ERROR)
            }
        }
    }

    private fun cancelOperation() {
        setResult(RESULT_CANCELED, request.cancelledResult())
        // The sheet goes away before onDestroy, so stop running operations now
        scope.cancel()
        finish()
    }

    /**
     * Compute the origin for clientDataJSON.
     * For privileged apps (browsers), use their provided origin via the allowlist.
     * For regular Android apps, compute from the signing certificate.
     */
    private fun computeOrigin(): String {
        val appInfo = request.callingAppInfo

        // Try to get origin using the privileged apps allowlist (for browsers)
        try {
            val allowlist = loadPrivilegedAllowlist()
            if (allowlist != null) {
                val origin = appInfo.getOrigin(allowlist)
                if (origin != null) {
                    return origin.removeSuffix("/")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get privileged origin", e)
        }

        // For regular Android apps, compute origin from signing certificate
        return try {
            val signingInfo = appInfo.signingInfo
            val cert = signingInfo.apkContentsSigners[0].toByteArray()
            val md = MessageDigest.getInstance("SHA-256")
            val certHash = md.digest(cert)
            "android:apk-key-hash:${Base64.encodeToString(certHash, Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE)}"
        } catch (e: Exception) {
            Log.e(TAG, "Failed to compute origin", e)
            "android:apk-key-hash:${appInfo.packageName}"
        }
    }

    private fun loadPrivilegedAllowlist(): String? {
        return try {
            resources.openRawResource(R.raw.privileged_apps).bufferedReader().use { it.readText() }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load privileged apps allowlist", e)
            null
        }
    }

    companion object {
        private const val TAG = "CredProviderActivity"
        private const val ACTION_USB_PERMISSION = "pl.lebihan.authnkey.CRED_USB_PERMISSION"

        // SPKI AlgorithmIdentifier for EC P-256: OID 1.2.840.10045.2.1 + OID 1.2.840.10045.3.1.7
        private val EC2_P256_ALGORITHM_ID = byteArrayOf(
            0x30, 0x13,
            0x06, 0x07, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07
        )

        // SPKI AlgorithmIdentifier for Ed25519: OID 1.3.101.112
        private val OKP_ED25519_ALGORITHM_ID = byteArrayOf(
            0x30, 0x05,
            0x06, 0x03, 0x2B, 0x65, 0x70
        )
    }
}
