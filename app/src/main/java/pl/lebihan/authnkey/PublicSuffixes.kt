package pl.lebihan.authnkey

import android.content.Context
import pl.lebihan.etldx.PublicSuffixList

/**
 * Holds the parsed public suffix list.
 *
 * Parsing walks the whole list, so it is done once and the instance kept. [PublicSuffixList] is
 * immutable and thread safe.
 */
object PublicSuffixes {

    @Volatile
    private var instance: PublicSuffixList? = null

    /** Returns the list, parsing it on first use. Call from a background thread. */
    fun get(context: Context): PublicSuffixList =
        instance ?: synchronized(this) {
            instance ?: PublicSuffixList(
                context.applicationContext.resources.openRawResource(R.raw.public_suffix_list)
            ).also { instance = it }
        }
}
