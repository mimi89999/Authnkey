package pl.lebihan.authnkey

import android.animation.ObjectAnimator
import android.content.Context
import android.content.DialogInterface
import android.content.res.ColorStateList
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.button.MaterialButton

class CredentialBottomSheet : BottomSheetDialogFragment() {

    enum class State {
        WAITING,
        TOUCH,
        PROCESSING,
        PIN,
        BIOMETRIC,
        ACCOUNT_SELECT,
        SUCCESS,
        TAG_LOST,
        ERROR
    }

    data class AccountInfo(
        val displayName: String,
        val subtitle: String? = null
    )

    private lateinit var statusText: TextView
    private lateinit var instructionText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var btnCancel: MaterialButton
    private lateinit var btnContinue: MaterialButton
    private lateinit var btnBiometric: MaterialButton
    private lateinit var pinInputField: PinInputField
    private lateinit var iconStatus: ImageView
    private lateinit var iconBackground: View
    private lateinit var accountList: RecyclerView

    private var pulseAnimator: ObjectAnimator? = null

    private var pendingStatus: String? = null
    private var pendingInstruction: String? = null
    private var pendingShowPinInput: Boolean = false
    private var pendingState: State = State.WAITING

    var onCancelClick: (() -> Unit)? = null
    var onPinEntered: ((String) -> Unit)? = null
    var onAccountSelected: ((Int) -> Unit)? = null
    var onBiometricSelected: (() -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        arguments?.let {
            pendingStatus = it.getString(ARG_STATUS)
            pendingInstruction = it.getString(ARG_INSTRUCTION)
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.bottom_sheet_credential, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        statusText = view.findViewById(R.id.statusText)
        instructionText = view.findViewById(R.id.instructionText)
        progressBar = view.findViewById(R.id.progressBar)
        btnCancel = view.findViewById(R.id.btnCancel)
        btnContinue = view.findViewById(R.id.btnContinue)
        btnBiometric = view.findViewById(R.id.btnBiometric)
        pinInputField = view.findViewById(R.id.pinInputField)
        iconStatus = view.findViewById(R.id.iconStatus)
        iconBackground = view.findViewById(R.id.iconBackground)
        accountList = view.findViewById(R.id.accountList)

        accountList.layoutManager = LinearLayoutManager(context)

        // Configure PIN input field
        pinInputField.useNumericKeyboard = getKeyboardPreference()
        pinInputField.onKeyboardModeChanged = { saveKeyboardPreference(it) }

        pendingStatus?.let { statusText.text = it }
        pendingInstruction?.let { instructionText.text = it }

        if (pendingShowPinInput) {
            pinInputField.visibility = View.VISIBLE
            btnContinue.visibility = View.VISIBLE
            pinInputField.focus()
        }

        applyState(pendingState)

        btnCancel.setOnClickListener {
            onCancelClick?.invoke()
        }

        btnContinue.setOnClickListener {
            submitPin()
        }

        btnBiometric.setOnClickListener {
            onBiometricSelected?.invoke()
        }

        pinInputField.setOnDoneAction {
            submitPin()
        }

        (dialog as? BottomSheetDialog)?.behavior?.apply {
            state = BottomSheetBehavior.STATE_EXPANDED
            skipCollapsed = true
        }
    }

    override fun onDestroyView() {
        stopPulse()
        super.onDestroyView()
    }

    override fun onCancel(dialog: DialogInterface) {
        super.onCancel(dialog)
        onCancelClick?.invoke()
    }

    private fun submitPin() {
        pinInputField.validateAndGetPin()?.let { pin ->
            onPinEntered?.invoke(pin)
        }
    }

    private fun getKeyboardPreference(): Boolean =
        requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(PREF_USE_NUMERIC_KEYBOARD, true)

    private fun saveKeyboardPreference(numeric: Boolean) {
        requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit { putBoolean(PREF_USE_NUMERIC_KEYBOARD, numeric) }
    }

    fun setState(state: State) {
        if (::iconStatus.isInitialized) {
            applyState(state)
        } else {
            pendingState = state
        }
    }

    private fun applyState(state: State) {
        stopPulse()

        val iconRes = when (state) {
            State.WAITING -> R.drawable.sensors_24
            State.TOUCH -> R.drawable.fingerprint_24
            State.PROCESSING -> R.drawable.key_24
            State.PIN -> R.drawable.lock_24
            State.BIOMETRIC -> R.drawable.fingerprint_24
            State.ACCOUNT_SELECT -> R.drawable.account_circle_24
            State.SUCCESS -> R.drawable.check_circle_24
            State.TAG_LOST -> R.drawable.sensors_24
            State.ERROR -> R.drawable.error_24
        }

        iconStatus.setImageResource(iconRes)
        iconBackground.backgroundTintList = null

        when (state) {
            State.WAITING, State.TOUCH, State.BIOMETRIC -> startPulse()
            State.TAG_LOST -> {
                iconBackground.backgroundTintList = ColorStateList.valueOf(
                    ContextCompat.getColor(requireContext(), R.color.warning_container)
                )
                startPulse(750)
            }
            else -> {}
        }
    }

    private fun startPulse(durationMs: Long = 1000) {
        pulseAnimator = ObjectAnimator.ofFloat(iconBackground, View.ALPHA, 1f, 0.3f).apply {
            duration = durationMs
            repeatCount = ObjectAnimator.INFINITE
            repeatMode = ObjectAnimator.REVERSE
            interpolator = AccelerateDecelerateInterpolator()
            start()
        }
    }

    private fun stopPulse() {
        pulseAnimator?.cancel()
        pulseAnimator = null
        if (::iconBackground.isInitialized) {
            iconBackground.alpha = 1f
        }
    }

    fun setStatus(text: String) {
        if (::statusText.isInitialized) {
            statusText.text = text
        } else {
            pendingStatus = text
        }
    }

    fun setInstruction(text: String) {
        if (::instructionText.isInitialized) {
            instructionText.text = text
        } else {
            pendingInstruction = text
        }
    }

    fun showProgress(show: Boolean) {
        if (::progressBar.isInitialized) {
            progressBar.visibility = if (show) View.VISIBLE else View.GONE
        }
    }

    fun showPinInput(show: Boolean) {
        if (::pinInputField.isInitialized) {
            pinInputField.visibility = if (show) View.VISIBLE else View.GONE
            btnContinue.visibility = if (show) View.VISIBLE else View.GONE
            if (show) {
                hideAccounts()
                pinInputField.clear()
                setState(State.PIN)
                pinInputField.focus()
            } else {
                hideBiometricOption()
            }
        } else {
            pendingShowPinInput = show
            if (show) pendingState = State.PIN
        }
    }

    fun showBiometricOption(show: Boolean) {
        if (::btnBiometric.isInitialized) {
            btnBiometric.visibility = if (show) View.VISIBLE else View.GONE
        }
    }

    fun hideBiometricOption() {
        if (::btnBiometric.isInitialized) {
            btnBiometric.visibility = View.GONE
        }
    }

    fun showBiometricWaiting() {
        if (::pinInputField.isInitialized) {
            pinInputField.visibility = View.GONE
            btnContinue.visibility = View.GONE
            hideBiometricOption()
            hideAccounts()
            setState(State.BIOMETRIC)
        }
    }

    fun showAccounts(accounts: List<AccountInfo>) {
        if (!::accountList.isInitialized) return

        setState(State.ACCOUNT_SELECT)
        pinInputField.visibility = View.GONE
        btnContinue.visibility = View.GONE
        hideBiometricOption()
        accountList.visibility = View.VISIBLE
        accountList.adapter = AccountAdapter(accounts) { index ->
            onAccountSelected?.invoke(index)
        }
    }

    fun hideAccounts() {
        if (::accountList.isInitialized) {
            accountList.visibility = View.GONE
        }
    }

    fun setPinError(error: String?) {
        if (::pinInputField.isInitialized) {
            pinInputField.error = error
        }
    }

    fun getCurrentPinIfValid(): String? {
        if (!::pinInputField.isInitialized) return null
        val pin = pinInputField.pin ?: return null
        return if (pin.length >= pinInputField.minPinLength) pin else null
    }

    private class AccountAdapter(
        private val accounts: List<AccountInfo>,
        private val onItemClick: (Int) -> Unit
    ) : RecyclerView.Adapter<AccountAdapter.ViewHolder>() {

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val name: TextView = view.findViewById(R.id.accountName)
            val subtitle: TextView = view.findViewById(R.id.accountSubtitle)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_account, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val account = accounts[position]
            holder.name.text = account.displayName
            if (account.subtitle != null) {
                holder.subtitle.text = account.subtitle
                holder.subtitle.visibility = View.VISIBLE
            } else {
                holder.subtitle.visibility = View.GONE
            }
            holder.itemView.setOnClickListener {
                onItemClick(position)
            }
        }

        override fun getItemCount() = accounts.size
    }

    companion object {
        const val TAG = "CredentialBottomSheet"
        private const val ARG_STATUS = "status"
        private const val ARG_INSTRUCTION = "instruction"
        private const val PREFS_NAME = "authnkey_prefs"
        private const val PREF_USE_NUMERIC_KEYBOARD = "use_numeric_keyboard"

        fun newInstance(status: String, instruction: String): CredentialBottomSheet {
            return CredentialBottomSheet().apply {
                arguments = Bundle().apply {
                    putString(ARG_STATUS, status)
                    putString(ARG_INSTRUCTION, instruction)
                }
            }
        }
    }
}
