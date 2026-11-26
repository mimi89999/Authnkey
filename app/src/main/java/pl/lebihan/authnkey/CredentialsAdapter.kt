package pl.lebihan.authnkey

import android.content.Context
import android.content.res.ColorStateList
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton

/**
 * Data class representing a credential with its relying party info
 */
data class CredentialItem(
    val rpId: String,
    val credential: CredentialManagement.Credential
)

/**
 * RecyclerView adapter for displaying credentials in a dialog
 */
class CredentialsAdapter(
    credentials: List<CredentialItem>,
    private val onDeleteClick: (CredentialItem) -> Unit
) : RecyclerView.Adapter<CredentialsAdapter.ViewHolder>() {

    private val allCredentials = credentials.toMutableList()
    private val credentials = credentials.toMutableList()
    private var expandedPosition: Int = RecyclerView.NO_POSITION

    /** Number of credentials, ignoring the search filter. */
    val count: Int get() = allCredentials.size

    /** Number of credentials matching the search filter. */
    val visibleCount: Int get() = credentials.size

    companion object {
        private val STRIP_PREFIXES = listOf("www.", "m.", "login.", "accounts.", "account.", "auth.")
        private val WHITESPACE = Regex("\\s+")
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val credentialRow: View = view.findViewById(R.id.credentialRow)
        val avatarBackground: View = view.findViewById(R.id.avatarBackground)
        val avatarLetter: TextView = view.findViewById(R.id.avatarLetter)
        val rpIdText: TextView = view.findViewById(R.id.rpIdText)
        val userText: TextView = view.findViewById(R.id.userText)
        val expandIcon: ImageView = view.findViewById(R.id.expandIcon)
        val detailsContainer: LinearLayout = view.findViewById(R.id.detailsContainer)
        val displayNameRow: View = view.findViewById(R.id.displayNameRow)
        val displayNameValue: TextView = view.findViewById(R.id.displayNameValue)
        val usernameRow: View = view.findViewById(R.id.usernameRow)
        val usernameValue: TextView = view.findViewById(R.id.usernameValue)
        val userIdRow: View = view.findViewById(R.id.userIdRow)
        val userIdValue: TextView = view.findViewById(R.id.userIdValue)
        val credentialIdValue: TextView = view.findViewById(R.id.credentialIdValue)
        val protectionRow: View = view.findViewById(R.id.protectionRow)
        val protectionValue: TextView = view.findViewById(R.id.protectionValue)
        val deleteButton: MaterialButton = view.findViewById(R.id.deleteButton)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_credential, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = credentials[position]
        val context = holder.itemView.context
        val isExpanded = position == expandedPosition

        val letter = getDisplayLetter(item.rpId)
        holder.avatarLetter.text = letter.toString()

        val (bgColor, textColor) = getAvatarColors(context, letter)
        holder.avatarBackground.backgroundTintList = ColorStateList.valueOf(bgColor)
        holder.avatarLetter.setTextColor(textColor)

        holder.rpIdText.text = item.rpId
        holder.userText.text = item.credential.userDisplayName
            ?: item.credential.userName
            ?: context.getString(R.string.unknown_account)

        holder.detailsContainer.visibility = if (isExpanded) View.VISIBLE else View.GONE
        holder.expandIcon.rotation = if (isExpanded) 180f else 0f

        holder.credentialRow.setOnClickListener {
            val previousExpanded = expandedPosition
            val adapterPosition = holder.bindingAdapterPosition

            if (adapterPosition == RecyclerView.NO_POSITION) return@setOnClickListener

            expandedPosition = if (isExpanded) RecyclerView.NO_POSITION else adapterPosition

            if (previousExpanded != RecyclerView.NO_POSITION) {
                notifyItemChanged(previousExpanded)
            }
            if (expandedPosition != RecyclerView.NO_POSITION) {
                notifyItemChanged(expandedPosition)
            }
        }

        holder.deleteButton.setOnClickListener {
            onDeleteClick(item)
        }

        if (isExpanded) {
            if (item.credential.userDisplayName != null) {
                holder.displayNameRow.visibility = View.VISIBLE
                holder.displayNameValue.text = item.credential.userDisplayName
            } else {
                holder.displayNameRow.visibility = View.GONE
            }

            if (item.credential.userName != null) {
                holder.usernameRow.visibility = View.VISIBLE
                holder.usernameValue.text = item.credential.userName
            } else {
                holder.usernameRow.visibility = View.GONE
            }

            if (item.credential.userId != null) {
                holder.userIdRow.visibility = View.VISIBLE
                holder.userIdValue.text = item.credential.userId.toHex()
            } else {
                holder.userIdRow.visibility = View.GONE
            }

            holder.credentialIdValue.text = item.credential.credentialId.toHex()

            if (item.credential.credProtect != null) {
                holder.protectionRow.visibility = View.VISIBLE
                holder.protectionValue.text = formatCredProtect(item.credential.credProtect)
            } else {
                holder.protectionRow.visibility = View.GONE
            }
        }
    }

    override fun getItemCount() = credentials.size

    /**
     * Shows only the credentials matching [query].
     *
     * The query is split on whitespace and every term has to appear, ignoring case, in the rpId, the
     * user name or the display name. Display names are not reliable (some RPs leave them out or prefix
     * them), so all three fields are searched, and "github john" finds john@example.com on github.com.
     */
    fun setQuery(query: String) {
        val terms = query.split(WHITESPACE).filter { it.isNotEmpty() }
        val oldList = credentials.toList()
        val newList = allCredentials.filter { item ->
            val fields = listOfNotNull(item.rpId, item.credential.userName, item.credential.userDisplayName)
            terms.all { term -> fields.any { it.contains(term, ignoreCase = true) } }
        }

        // Items are shared with allCredentials and never change, so identity is enough.
        // Filtering keeps the order, so there are no moves to detect.
        val diff = DiffUtil.calculateDiff(object : DiffUtil.Callback() {
            override fun getOldListSize() = oldList.size
            override fun getNewListSize() = newList.size
            override fun areItemsTheSame(oldPos: Int, newPos: Int) = oldList[oldPos] === newList[newPos]
            override fun areContentsTheSame(oldPos: Int, newPos: Int) = true
        }, false)

        val expandedItem = credentials.getOrNull(expandedPosition)
        credentials.clear()
        credentials.addAll(newList)
        // indexOf gives -1 (NO_POSITION) when the expanded credential got filtered out
        expandedPosition = expandedItem?.let(credentials::indexOf) ?: RecyclerView.NO_POSITION

        diff.dispatchUpdatesTo(this)
    }

    fun removeItem(item: CredentialItem) {
        allCredentials.remove(item)

        val position = credentials.indexOf(item)
        if (position == -1) return

        credentials.removeAt(position)

        when {
            expandedPosition == position -> expandedPosition = RecyclerView.NO_POSITION
            expandedPosition > position -> expandedPosition--
        }

        notifyItemRemoved(position)
    }

    /**
     * Get the display letter for a domain, stripping common prefixes
     */
    private fun getDisplayLetter(rpId: String): Char {
        var domain = rpId.lowercase()
        for (prefix in STRIP_PREFIXES) {
            if (domain.startsWith(prefix)) {
                domain = domain.removePrefix(prefix)
                break
            }
        }
        return domain.firstOrNull()?.uppercaseChar() ?: '?'
    }

    /**
     * Get avatar colors based on the letter
     */
    private fun getAvatarColors(context: Context, letter: Char): Pair<Int, Int> {
        val bgColors = context.resources.getIntArray(R.array.avatar_background_colors)
        val textColors = context.resources.getIntArray(R.array.avatar_text_colors)

        val index = (letter.code * 7) % bgColors.size
        return Pair(bgColors[index], textColors[index])
    }

    /**
     * Format credential protection level
     */
    private fun formatCredProtect(level: Int): String = when (level) {
        1 -> "userVerificationOptional"
        2 -> "userVerificationOptionalWithCredentialIDList"
        3 -> "userVerificationRequired"
        else -> "unknown ($level)"
    }
}
