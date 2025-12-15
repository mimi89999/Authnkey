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
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import kotlinx.coroutines.*
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import java.security.MessageDigest

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialProviderActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private lateinit var usbManager: UsbManager

    private var bottomSheet: CredentialBottomSheet? = null

    private var currentTransport: FidoTransport? = null
    private var pinProtocol: PinProtocol? = null
    private var deviceInfo: DeviceInfo? = null

    private var createRequest: ProviderCreateCredentialRequest? = null
    private var getRequest: ProviderGetCredentialRequest? = null
    private var callingAppInfo: CallingAppInfo? = null
    private var requestJson: String? = null
    private var isCreateRequest: Boolean = false
    private var pendingPin: String? = null  // PIN entered before key connection
    private var userVerification: UserVerification = UserVerification.PREFERRED

    private enum class UserVerification {
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
                    setInstruction(getString(R.string.instruction_usb_permission_denied))
                }
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

        // Use PendingIntentHandler to retrieve the proper request objects
        // This is the correct way per Android documentation
        createRequest = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        getRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)

        when {
            createRequest != null -> {
                isCreateRequest = true
                callingAppInfo = createRequest!!.callingAppInfo
                val publicKeyRequest = createRequest!!.callingRequest as? CreatePublicKeyCredentialRequest
                requestJson = publicKeyRequest?.requestJson
                showBottomSheet(getString(R.string.create_passkey), getString(R.string.instruction_connect_key))
            }
            getRequest != null -> {
                isCreateRequest = false
                callingAppInfo = getRequest!!.callingAppInfo
                val options = getRequest!!.credentialOptions
                val publicKeyOption = options.firstOrNull { it is GetPublicKeyCredentialOption } as? GetPublicKeyCredentialOption
                requestJson = publicKeyOption?.requestJson
                showBottomSheet(getString(R.string.sign_in), getString(R.string.instruction_connect_key))
            }
            else -> {
                Log.e(TAG, "No valid request found in intent")
                cancelOperation()
                return
            }
        }

        if (requestJson == null) {
            Log.e(TAG, "No request JSON")
            cancelOperation()
            return
        }

        // Check if PIN is likely required based on userVerification preference
        checkPinRequirement()
    }

    private fun showBottomSheet(status: String, instruction: String) {
        bottomSheet = CredentialBottomSheet.newInstance(status, instruction).apply {
            onCancelClick = { cancelOperation() }
            onPinEntered = { pin -> handlePinEntered(pin) }
        }
        bottomSheet?.show(supportFragmentManager, CredentialBottomSheet.TAG)
        bottomSheet?.setState(CredentialBottomSheet.State.WAITING)
    }

    private fun handlePinEntered(pin: String) {
        if (currentTransport?.isConnected == true) {
            val json = JSONObject(requestJson!!)
            showProgress(true)
            setInstruction(getString(R.string.instruction_verifying))
            setState(CredentialBottomSheet.State.PROCESSING)
            bottomSheet?.showPinInput(false)
            authenticateAndExecute(pin, json)
        } else {
            pendingPin = pin
            setInstruction(getString(R.string.instruction_connect_key))
            setState(CredentialBottomSheet.State.WAITING)
            bottomSheet?.showPinInput(false)
        }
    }

    private fun setStatus(text: String) {
        bottomSheet?.setStatus(text)
    }

    private fun setInstruction(text: String) {
        bottomSheet?.setInstruction(text)
    }

    private fun showProgress(show: Boolean) {
        bottomSheet?.showProgress(show)
    }

    private fun setState(state: CredentialBottomSheet.State) {
        bottomSheet?.setState(state)
    }

    private fun checkPinRequirement() {
        try {
            val json = JSONObject(requestJson!!)

            // Check userVerification in authenticatorSelection (create) or directly (get)
            val uvString = if (isCreateRequest) {
                json.optJSONObject("authenticatorSelection")?.optString("userVerification", "preferred")
            } else {
                json.optString("userVerification", "preferred")
            }
            userVerification = UserVerification.fromString(uvString)

            // Check if allowCredentials is empty (discoverable credential flow needs PIN)
            val allowCredentialsEmpty = if (!isCreateRequest) {
                !json.has("allowCredentials") || json.getJSONArray("allowCredentials").length() == 0
            } else false

            // For required/preferred, or discoverable flow, ask for PIN upfront to minimize NFC taps
            if (userVerification != UserVerification.DISCOURAGED || allowCredentialsEmpty) {
                showPinDialogFirst()
            }
            // If discouraged with allowCredentials, just wait for key connection

        } catch (e: Exception) {
            Log.e(TAG, "Error checking PIN requirement", e)
            // Assume preferred
            userVerification = UserVerification.PREFERRED
            showPinDialogFirst()
        }
    }

    private fun showPinDialogFirst() {
        setInstruction(getString(R.string.instruction_enter_pin))
        setState(CredentialBottomSheet.State.PIN)
        bottomSheet?.showPinInput(true)
    }

    override fun onResume() {
        super.onResume()

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

        if (currentTransport == null) {
            checkForUsbDevice()
        }
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(usbPermissionReceiver)
        } catch (e: Exception) {
            // Ignore
        }
        scope.cancel()
        currentTransport?.close()
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
        val devices = usbManager.deviceList.values.filter { UsbTransport.isFidoDevice(it) }
        if (devices.isNotEmpty()) {
            val device = devices.first()
            if (usbManager.hasPermission(device)) {
                connectToUsbDevice(device)
            } else {
                requestUsbPermission(device)
            }
        }
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

    private fun handleNfcTag(tag: Tag) {
        scope.launch {
            try {
                currentTransport?.close()

                // Capture any valid PIN and hide input
                bottomSheet?.getCurrentPinIfValid()?.let { pendingPin = it }
                bottomSheet?.showPinInput(false)

                val isoDep = IsoDep.get(tag) ?: throw Exception("Not an ISO-DEP tag")
                val transport = NfcTransport(isoDep)

                if (!transport.selectFidoApplet()) {
                    throw Exception("Failed to select FIDO applet")
                }

                currentTransport = transport
                pinProtocol = PinProtocol(transport)

                setInstruction(getString(R.string.instruction_key_connected))
                setState(CredentialBottomSheet.State.PROCESSING)
                showProgress(true)

                processRequest()

            } catch (e: Exception) {
                Log.e(TAG, "NFC error", e)
                setInstruction(getString(R.string.error_retry_format, e.message ?: "Unknown error"))
                setState(CredentialBottomSheet.State.ERROR)
                showProgress(false)
            }
        }
    }

    private fun connectToUsbDevice(device: UsbDevice) {
        scope.launch {
            try {
                currentTransport?.close()

                // Capture any valid PIN and hide input
                bottomSheet?.getCurrentPinIfValid()?.let { pendingPin = it }
                bottomSheet?.showPinInput(false)

                setInstruction(getString(R.string.instruction_connecting_usb))
                setState(CredentialBottomSheet.State.PROCESSING)

                val transport = withContext(Dispatchers.IO) {
                    UsbTransport.create(usbManager, device)
                } ?: throw Exception("Failed to initialize USB connection")

                currentTransport = transport
                pinProtocol = PinProtocol(transport)

                setInstruction(getString(R.string.instruction_key_connected))
                showProgress(true)

                processRequest()

            } catch (e: Exception) {
                Log.e(TAG, "USB error", e)
                setInstruction(getString(R.string.error_retry_format, e.message ?: "Unknown error"))
                setState(CredentialBottomSheet.State.ERROR)
                showProgress(false)
            }
        }
    }

    private fun processRequest() {
        scope.launch {
            try {
                val json = JSONObject(requestJson!!)
                val transport = currentTransport ?: throw Exception("No transport")
                val protocol = pinProtocol ?: throw Exception("No PIN protocol")

                // Get device info to check PIN requirements and CTAP version
                val infoResponse = withContext(Dispatchers.IO) {
                    transport.sendCtapCommand(CTAP.buildCommand(CTAP.CMD_GET_INFO))
                }
                deviceInfo = CTAP.parseGetInfoStructured(infoResponse)

                // Check if clientPin is actually set on the device
                val deviceHasPin = deviceInfo?.options?.get("clientPin") == true
                val alwaysUv = deviceInfo?.options?.get("alwaysUv") == true

                when {
                    // We already have PIN from pre-prompt
                    deviceHasPin && pendingPin != null -> {
                        setInstruction(getString(R.string.instruction_authenticating))
                        authenticateAndExecute(pendingPin!!, json)
                    }
                    // UV required but device has no PIN - fail
                    userVerification == UserVerification.REQUIRED && !deviceHasPin -> {
                        throw Exception(getString(R.string.error_uv_required_no_pin))
                    }
                    // UV required/preferred and device has PIN - need to get PIN
                    userVerification != UserVerification.DISCOURAGED && deviceHasPin -> {
                        val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() } ?: 8
                        showPinDialog(retries, json)
                    }
                    // UV discouraged but device has alwaysUv - need PIN anyway
                    userVerification == UserVerification.DISCOURAGED && alwaysUv && deviceHasPin -> {
                        val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() } ?: 8
                        showPinDialog(retries, json)
                    }
                    // UV discouraged or preferred with no PIN - try without
                    else -> {
                        tryExecuteWithoutPin(json)
                    }
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error processing request", e)
                handleError(e)
            }
        }
    }

    private fun tryExecuteWithoutPin(json: JSONObject) {
        scope.launch {
            try {
                executeRequest(json, null)
            } catch (e: Exception) {
                // Check if authenticator requires PIN despite UV=discouraged
                val errorMsg = e.message ?: ""
                if (errorMsg.contains("PIN_REQUIRED") ||
                    errorMsg.contains("PIN_AUTH_INVALID") ||
                    errorMsg.contains("0x36") ||  // CTAP2_ERR_PUAT_REQUIRED
                    errorMsg.contains("0x44")) {  // CTAP2_ERR_PIN_REQUIRED
                    // Authenticator requires PIN, ask user
                    Log.d(TAG, "Authenticator requires PIN despite UV=discouraged")
                    val protocol = pinProtocol ?: throw Exception("No PIN protocol")
                    val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() } ?: 8
                    showPinDialog(retries, json)
                } else {
                    throw e
                }
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
                val protocol = pinProtocol ?: throw Exception("PIN protocol not initialized")

                setInstruction(getString(R.string.instruction_initializing))
                val initialized = withContext(Dispatchers.IO) { protocol.initialize() }
                if (!initialized) {
                    throw Exception("Failed to initialize PIN protocol")
                }

                // Determine permissions and rpId based on operation type
                val permissions: Int
                val rpId: String?

                if (isCreateRequest) {
                    permissions = PinProtocol.PERMISSION_MC
                    rpId = requestJson.getJSONObject("rp").getString("id")
                } else {
                    permissions = PinProtocol.PERMISSION_GA
                    rpId = requestJson.getString("rpId")
                }

                setInstruction(getString(R.string.instruction_verifying_pin))
                // Try CTAP2.1 style with permissions first
                val authenticated = withContext(Dispatchers.IO) {
                    protocol.getPinToken(pin, permissions, rpId)
                }
                if (!authenticated) {
                    val retries = withContext(Dispatchers.IO) { protocol.getPinRetries() } ?: 0
                    if (retries > 0) {
                        runOnUiThread {
                            showProgress(false)
                            setInstruction(getString(R.string.pin_invalid_retries, retries))
                            setState(CredentialBottomSheet.State.PIN)
                            bottomSheet?.showPinInput(true)
                        }
                    } else {
                        throw Exception(getString(R.string.error_pin_blocked))
                    }
                    return@launch
                }

                executeRequest(requestJson, protocol)

            } catch (e: Exception) {
                Log.e(TAG, "Authentication error", e)
                handleError(e)
            }
        }
    }

    private suspend fun executeRequest(requestJson: JSONObject, pinProtocol: PinProtocol?) {
        try {
            val transport = currentTransport ?: throw Exception("No transport")

            if (isCreateRequest) {
                executeCreateCredential(transport, requestJson, pinProtocol)
            } else {
                executeGetAssertion(transport, requestJson, pinProtocol)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Execute error", e)
            handleError(e)
        }
    }

    private suspend fun executeCreateCredential(
        transport: FidoTransport,
        requestJson: JSONObject,
        pinProtocol: PinProtocol?
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

        val pubKeyCredParams = mutableListOf<Pair<String, Int>>()
        val paramsArray = requestJson.getJSONArray("pubKeyCredParams")
        for (i in 0 until paramsArray.length()) {
            val param = paramsArray.getJSONObject(i)
            pubKeyCredParams.add(Pair(param.getString("type"), param.getInt("alg")))
        }

        // Parse excludeCredentials if present
        val excludeList = mutableListOf<ByteArray>()
        if (requestJson.has("excludeCredentials")) {
            val excludeArray = requestJson.getJSONArray("excludeCredentials")
            for (i in 0 until excludeArray.length()) {
                val cred = excludeArray.getJSONObject(i)
                val id = Base64.decode(cred.getString("id"), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                excludeList.add(id)
            }
        }

        // Parse authenticatorSelection for residentKey requirement
        val authSelection = requestJson.optJSONObject("authenticatorSelection")
        val residentKey = ResidentKeyRequirement.fromString(
            authSelection?.optString("residentKey", "preferred")
        )

        // Build clientDataJSON with proper origin
        val origin = computeOrigin()

        val clientDataJson = JSONObject().apply {
            put("type", "webauthn.create")
            put("challenge", requestJson.getString("challenge"))
            put("origin", origin)
            put("crossOrigin", false)
        }.toString().replace("\\/", "/") // Android JSONObject escapes slashes

        val clientDataHash = FidoCommands.hashClientData(clientDataJson)

        // Compute pinUvAuthParam if needed
        var pinUvAuthParam: ByteArray? = null
        if (pinProtocol != null) {
            pinUvAuthParam = pinProtocol.computeAuthParam(clientDataHash)
        }

        // Build and send command
        val command = FidoCommands.buildMakeCredential(
            clientDataHash = clientDataHash,
            rpId = rpId,
            rpName = rpName,
            userId = userId,
            userName = userName,
            userDisplayName = userDisplayName,
            pubKeyCredParams = pubKeyCredParams,
            excludeList = if (excludeList.isNotEmpty()) excludeList else null,
            requireResidentKey = residentKey.requiresResidentKey(),
            requireUserVerification = false, // UV is provided by pinUvAuthParam
            pinUvAuthParam = pinUvAuthParam,
            pinUvAuthProtocol = if (pinProtocol != null) 1 else null
        )

        runOnUiThread {
            setInstruction(getString(R.string.instruction_touch_key))
            if (transport.transportType == TransportType.USB) {
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
            makeCredResult.authData,
            makeCredResult.attStmt
        )

        // Extract credential ID from authData
        val credentialId = extractCredentialIdFromAuthData(makeCredResult.authData)

        // Check if credProps extension was requested
        val extensions = requestJson.optJSONObject("extensions")
        val credPropsRequested = extensions?.optBoolean("credProps", false) ?: false

        // Determine if credential is actually discoverable
        // If we requested rk AND the authenticator supports it AND succeeded, it's discoverable
        val supportsResidentKey = deviceInfo?.options?.get("rk") ?: true
        val isDiscoverable = residentKey.requiresResidentKey() && supportsResidentKey

        // Build response JSON
        val responseJson = JSONObject().apply {
            put("id", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("rawId", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("type", "public-key")
            put("authenticatorAttachment", "cross-platform")
            put("response", JSONObject().apply {
                put("clientDataJSON", Base64.encodeToString(
                    clientDataJson.toByteArray(),
                    Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                ))
                put("attestationObject", Base64.encodeToString(
                    attestationObject,
                    Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                ))
                // Add transports array based on current transport
                put("transports", org.json.JSONArray().apply {
                    put(transport.transportType.webauthnName)
                })
            })
            put("clientExtensionResults", JSONObject().apply {
                if (credPropsRequested) {
                    put("credProps", JSONObject().apply {
                        put("rk", isDiscoverable)
                    })
                }
            })
        }

        returnCreateResult(responseJson.toString())
    }

    private suspend fun executeGetAssertion(
        transport: FidoTransport,
        requestJson: JSONObject,
        pinProtocol: PinProtocol?
    ) {
        setInstruction(getString(R.string.instruction_signing_in))

        // Parse request
        val rpId = requestJson.getString("rpId")
        val challenge = Base64.decode(
            requestJson.getString("challenge"),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )

        // Parse allowCredentials if present
        val allowList = mutableListOf<ByteArray>()
        if (requestJson.has("allowCredentials")) {
            val allowArray = requestJson.getJSONArray("allowCredentials")
            for (i in 0 until allowArray.length()) {
                val cred = allowArray.getJSONObject(i)
                val id = Base64.decode(cred.getString("id"), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                allowList.add(id)
            }
        }

        // Build clientDataJSON with proper origin
        val origin = computeOrigin()
        val clientDataJson = JSONObject().apply {
            put("type", "webauthn.get")
            put("challenge", requestJson.getString("challenge"))
            put("origin", origin)
            put("crossOrigin", false)
        }.toString().replace("\\/", "/") // Android JSONObject escapes slashes

        val clientDataHash = FidoCommands.hashClientData(clientDataJson)

        // Compute pinUvAuthParam if needed
        var pinUvAuthParam: ByteArray? = null
        if (pinProtocol != null) {
            pinUvAuthParam = pinProtocol.computeAuthParam(clientDataHash)
        }

        // Build and send command
        val command = FidoCommands.buildGetAssertion(
            rpId = rpId,
            clientDataHash = clientDataHash,
            allowList = if (allowList.isNotEmpty()) allowList else null,
            requireUserVerification = false, // UV is provided by pinUvAuthParam
            pinUvAuthParam = pinUvAuthParam,
            pinUvAuthProtocol = if (pinProtocol != null) 1 else null
        )

        runOnUiThread {
            setInstruction(getString(R.string.instruction_touch_key))
            if (transport.transportType == TransportType.USB) {
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

        // Get credential ID from response or allowList
        val credentialId = selectedAssertion.credential?.id
            ?: if (allowList.isNotEmpty()) allowList[0] else ByteArray(0)

        // Build response JSON
        val responseJson = JSONObject().apply {
            put("id", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("rawId", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            put("type", "public-key")
            put("authenticatorAttachment", "cross-platform")
            put("response", JSONObject().apply {
                put("clientDataJSON", Base64.encodeToString(
                    clientDataJson.toByteArray(),
                    Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                ))
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
            put("clientExtensionResults", JSONObject())
        }

        returnGetResult(responseJson.toString())
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
        authData: ByteArray,
        attStmt: Map<*, *>
    ): ByteArray {
        // Re-encode as CBOR
        val output = mutableListOf<Byte>()
        output.add(0xA3.toByte()) // map of 3 items

        // "fmt"
        output.add(0x63) // text string of 3 chars
        output.addAll("fmt".toByteArray().toList())
        val fmtBytes = fmt.toByteArray()
        if (fmtBytes.size < 24) {
            output.add((0x60 + fmtBytes.size).toByte())
        } else {
            output.add(0x78.toByte())
            output.add(fmtBytes.size.toByte())
        }
        output.addAll(fmtBytes.toList())

        // "authData"
        output.add(0x68) // text string of 8 chars
        output.addAll("authData".toByteArray().toList())
        if (authData.size < 24) {
            output.add((0x40 + authData.size).toByte())
        } else if (authData.size < 256) {
            output.add(0x58.toByte())
            output.add(authData.size.toByte())
        } else {
            output.add(0x59.toByte())
            output.add((authData.size shr 8).toByte())
            output.add((authData.size and 0xFF).toByte())
        }
        output.addAll(authData.toList())

        // "attStmt"
        output.add(0x67) // text string of 7 chars
        output.addAll("attStmt".toByteArray().toList())
        if (attStmt.isEmpty()) {
            output.add(0xA0.toByte()) // empty map
        } else {
            output.addAll(encodeAttStmt(attStmt))
        }

        return output.toByteArray()
    }

    private fun encodeAttStmt(attStmt: Map<*, *>): List<Byte> {
        val output = mutableListOf<Byte>()

        // Count items
        val items = attStmt.size
        if (items < 24) {
            output.add((0xA0 + items).toByte())
        } else {
            output.add(0xB8.toByte())
            output.add(items.toByte())
        }

        for ((key, value) in attStmt) {
            // Encode key (should be string)
            val keyStr = key.toString()
            val keyBytes = keyStr.toByteArray()
            if (keyBytes.size < 24) {
                output.add((0x60 + keyBytes.size).toByte())
            } else {
                output.add(0x78.toByte())
                output.add(keyBytes.size.toByte())
            }
            output.addAll(keyBytes.toList())

            // Encode value
            when (value) {
                is ByteArray -> {
                    if (value.size < 24) {
                        output.add((0x40 + value.size).toByte())
                    } else if (value.size < 256) {
                        output.add(0x58.toByte())
                        output.add(value.size.toByte())
                    } else {
                        output.add(0x59.toByte())
                        output.add((value.size shr 8).toByte())
                        output.add((value.size and 0xFF).toByte())
                    }
                    output.addAll(value.toList())
                }
                is List<*> -> {
                    // Array of byte arrays (e.g., x5c)
                    output.add((0x80 + value.size).toByte())
                    for (item in value) {
                        if (item is ByteArray) {
                            if (item.size < 24) {
                                output.add((0x40 + item.size).toByte())
                            } else if (item.size < 256) {
                                output.add(0x58.toByte())
                                output.add(item.size.toByte())
                            } else {
                                output.add(0x59.toByte())
                                output.add((item.size shr 8).toByte())
                                output.add((item.size and 0xFF).toByte())
                            }
                            output.addAll(item.toList())
                        }
                    }
                }
                is Number -> {
                    val intVal = value.toInt()
                    if (intVal >= 0 && intVal < 24) {
                        output.add(intVal.toByte())
                    } else if (intVal >= 0 && intVal < 256) {
                        output.add(0x18.toByte())
                        output.add(intVal.toByte())
                    } else if (intVal < 0) {
                        val encoded = -1 - intVal
                        if (encoded < 24) {
                            output.add((0x20 + encoded).toByte())
                        } else {
                            output.add(0x38.toByte())
                            output.add(encoded.toByte())
                        }
                    }
                }
                else -> {
                    // Skip unknown types
                    output.add(0xF6.toByte()) // null
                }
            }
        }

        return output
    }

    private fun extractCredentialIdFromAuthData(authData: ByteArray): ByteArray {
        // authData structure:
        // rpIdHash (32 bytes) + flags (1 byte) + signCount (4 bytes) + attestedCredentialData
        // attestedCredentialData: aaguid (16 bytes) + credentialIdLength (2 bytes) + credentialId + publicKey

        if (authData.size < 55) {
            return ByteArray(0)
        }

        val flags = authData[32].toInt() and 0xFF
        val hasAttestedCredData = (flags and 0x40) != 0

        if (!hasAttestedCredData) {
            return ByteArray(0)
        }

        // Skip rpIdHash (32) + flags (1) + signCount (4) + aaguid (16)
        val credIdLengthOffset = 32 + 1 + 4 + 16
        val credIdLength = ((authData[credIdLengthOffset].toInt() and 0xFF) shl 8) or
                (authData[credIdLengthOffset + 1].toInt() and 0xFF)

        val credIdOffset = credIdLengthOffset + 2
        return authData.sliceArray(credIdOffset until credIdOffset + credIdLength)
    }

    private fun returnCreateResult(responseJson: String) {
        val response = CreatePublicKeyCredentialResponse(responseJson)
        val resultData = Intent()
        PendingIntentHandler.setCreateCredentialResponse(resultData, response)
        setResult(RESULT_OK, resultData)
        finish()
    }

    private fun returnGetResult(responseJson: String) {
        val credential = PublicKeyCredential(responseJson)
        val response = GetCredentialResponse(credential)
        val resultData = Intent()
        PendingIntentHandler.setGetCredentialResponse(resultData, response)
        setResult(RESULT_OK, resultData)
        finish()
    }

    private fun handleError(e: Exception) {
        runOnUiThread {
            showProgress(false)
            setInstruction(getString(R.string.error_format, e.message ?: "Unknown error"))
            setState(CredentialBottomSheet.State.ERROR)
        }
    }

    private fun cancelOperation() {
        if (isCreateRequest) {
            val resultData = Intent()
            PendingIntentHandler.setCreateCredentialException(
                resultData,
                CreateCredentialUnknownException("User cancelled")
            )
            setResult(RESULT_CANCELED, resultData)
        } else {
            val resultData = Intent()
            PendingIntentHandler.setGetCredentialException(
                resultData,
                GetCredentialUnknownException("User cancelled")
            )
            setResult(RESULT_CANCELED, resultData)
        }
        finish()
    }

    /**
     * Compute the origin for clientDataJSON.
     * For privileged apps (browsers), use their provided origin via the allowlist.
     * For regular Android apps, compute from the signing certificate.
     */
    private fun computeOrigin(): String {
        val appInfo = callingAppInfo ?: return "android:apk-key-hash:unknown"

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
    }
}
