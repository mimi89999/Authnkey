package pl.lebihan.authnkey

import android.animation.ObjectAnimator
import android.content.DialogInterface
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

class CredentialBottomSheet : BottomSheetDialogFragment() {

    enum class State {
        WAITING,
        TOUCH,
        PROCESSING,
        PIN,
        ACCOUNT_SELECT,
        SUCCESS,
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
    private lateinit var pinInputLayout: TextInputLayout
    private lateinit var pinEditText: TextInputEditText
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
        pinInputLayout = view.findViewById(R.id.pinInputLayout)
        pinEditText = view.findViewById(R.id.pinEditText)
        iconStatus = view.findViewById(R.id.iconStatus)
        iconBackground = view.findViewById(R.id.iconBackground)
        accountList = view.findViewById(R.id.accountList)

        accountList.layoutManager = LinearLayoutManager(context)

        pendingStatus?.let { statusText.text = it }
        pendingInstruction?.let { instructionText.text = it }

        if (pendingShowPinInput) {
            pinInputLayout.visibility = View.VISIBLE
            btnContinue.visibility = View.VISIBLE
            pinEditText.requestFocus()
        }

        applyState(pendingState)

        btnCancel.setOnClickListener {
            onCancelClick?.invoke()
        }

        btnContinue.setOnClickListener {
            submitPin()
        }

        pinEditText.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                submitPin()
                true
            } else {
                false
            }
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
        val pin = pinEditText.text?.toString() ?: ""
        if (pin.length >= 4) {
            pinInputLayout.error = null
            onPinEntered?.invoke(pin)
        } else {
            pinInputLayout.error = getString(R.string.pin_too_short)
        }
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
            State.ACCOUNT_SELECT -> R.drawable.account_circle_24
            State.SUCCESS -> R.drawable.check_circle_24
            State.ERROR -> R.drawable.error_24
        }

        iconStatus.setImageResource(iconRes)

        when (state) {
            State.WAITING, State.TOUCH -> startPulse()
            else -> {}
        }
    }

    private fun startPulse() {
        pulseAnimator = ObjectAnimator.ofFloat(iconBackground, View.ALPHA, 1f, 0.3f).apply {
            duration = 1000
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
        if (::pinInputLayout.isInitialized) {
            pinInputLayout.visibility = if (show) View.VISIBLE else View.GONE
            btnContinue.visibility = if (show) View.VISIBLE else View.GONE
            if (show) {
                hideAccounts()
                pinEditText.text?.clear()
                pinInputLayout.error = null
                pinEditText.requestFocus()
                setState(State.PIN)
                pinEditText.post {
                    val imm = requireContext().getSystemService(InputMethodManager::class.java)
                    imm?.showSoftInput(pinEditText, InputMethodManager.SHOW_IMPLICIT)
                }
            } else {
                val imm = requireContext().getSystemService(InputMethodManager::class.java)
                imm?.hideSoftInputFromWindow(pinEditText.windowToken, 0)
            }
        } else {
            pendingShowPinInput = show
            if (show) pendingState = State.PIN
        }
    }

    fun showAccounts(accounts: List<AccountInfo>) {
        if (!::accountList.isInitialized) return

        setState(State.ACCOUNT_SELECT)
        pinInputLayout.visibility = View.GONE
        btnContinue.visibility = View.GONE
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
        if (::pinInputLayout.isInitialized) {
            pinInputLayout.error = error
        }
    }

    fun getCurrentPinIfValid(): String? {
        if (!::pinEditText.isInitialized) return null
        val pin = pinEditText.text?.toString() ?: return null
        return if (pin.length >= 4) pin else null
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
