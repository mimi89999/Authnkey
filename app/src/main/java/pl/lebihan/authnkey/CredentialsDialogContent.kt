package pl.lebihan.authnkey

import android.content.Context
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.TextView
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

class CredentialsDialogContent(
    context: Context,
    credentials: List<CredentialItem>,
    initialRemaining: Int,
    onDelete: (CredentialItem) -> Unit
) {
    companion object {
        /** The search field is only shown when the list holds more credentials than this. */
        private const val SEARCH_THRESHOLD = 10
    }

    private var remainingSlots = initialRemaining

    val view: View = LayoutInflater.from(context).inflate(R.layout.dialog_credentials, null)

    private val searchLayout: View = view.findViewById(R.id.searchLayout)
    private val searchInput: EditText = view.findViewById(R.id.searchInput)
    private val statsText: TextView = view.findViewById(R.id.statsText)
    private val recyclerView: RecyclerView = view.findViewById(R.id.credentialList)
    private val noResultsText: View = view.findViewById(R.id.noResultsText)
    private val emptyState: View = view.findViewById(R.id.emptyState)
    private val adapter: CredentialsAdapter = CredentialsAdapter(credentials, onDelete)

    init {
        recyclerView.layoutManager = LinearLayoutManager(context)
        recyclerView.adapter = adapter

        // Decided once, so the field does not vanish while deleting from a filtered list
        if (credentials.size > SEARCH_THRESHOLD) {
            setUpSearch()
        }

        updateVisibility()
        updateStats()
    }

    fun notifyDeleted(item: CredentialItem) {
        adapter.removeItem(item)
        remainingSlots++
        updateStats()
        updateVisibility()
    }

    private fun setUpSearch() {
        searchLayout.visibility = View.VISIBLE

        searchInput.doAfterTextChanged { text ->
            adapter.setQuery(text?.toString().orEmpty())
            recyclerView.scrollToPosition(0)
            updateVisibility()
        }

        searchInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_SEARCH) {
                leaveSearchField()
                true
            } else {
                false
            }
        }

        // Touching the list, to scroll or to open a credential, ends the search input
        recyclerView.addOnItemTouchListener(object : RecyclerView.SimpleOnItemTouchListener() {
            override fun onInterceptTouchEvent(rv: RecyclerView, e: MotionEvent): Boolean {
                if (e.actionMasked == MotionEvent.ACTION_DOWN && searchInput.hasFocus()) {
                    leaveSearchField()
                }
                return false
            }
        })
    }

    private fun leaveSearchField() {
        view.context.getSystemService(InputMethodManager::class.java)
            ?.hideSoftInputFromWindow(searchInput.windowToken, 0)
        searchInput.clearFocus()
    }

    private fun updateStats() {
        statsText.text = view.context.getString(
            R.string.credentials_stats,
            adapter.count,
            remainingSlots
        )
    }

    private fun updateVisibility() {
        val hasCredentials = adapter.count > 0
        val hasMatches = adapter.visibleCount > 0

        emptyState.visibility = if (hasCredentials) View.GONE else View.VISIBLE
        recyclerView.visibility = if (hasMatches) View.VISIBLE else View.GONE
        noResultsText.visibility = if (hasCredentials && !hasMatches) View.VISIBLE else View.GONE
    }
}
