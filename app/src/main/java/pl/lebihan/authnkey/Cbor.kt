package pl.lebihan.authnkey

import java.io.ByteArrayOutputStream

fun cbor(block: CborEncoder.() -> Unit): ByteArray = CborEncoder().apply(block).toByteArray()

@DslMarker
annotation class CborDsl

@CborDsl
class CborEncoder {
    private val out = ByteArrayOutputStream()

    fun map(block: CborMapEncoder.() -> Unit) {
        out.writeMap(CborMapEncoder().apply(block).entries)
    }

    fun toByteArray(): ByteArray = out.toByteArray()
}

@CborDsl
class CborMapEncoder {
    internal val entries = mutableListOf<Pair<ByteArray, ByteArray>>()

    infix fun Int.to(value: Any?) = put(this, value)
    infix fun String.to(value: Any?) = put(this, value)

    fun map(block: CborMapEncoder.() -> Unit): CborRaw = encodeMap(block)
    fun array(block: CborArrayEncoder.() -> Unit): CborRaw = encodeArray(block)
    fun bytes(data: ByteArray) = CborRaw(encodeValue(data))

    private fun put(key: Any, value: Any?) {
        entries += Pair(encodeValue(key), encodeValue(value))
    }
}

@CborDsl
class CborArrayEncoder {
    private val out = ByteArrayOutputStream()
    private var size = 0

    fun add(value: Any?) {
        out.write(encodeValue(value))
        size++
    }

    fun map(block: CborMapEncoder.() -> Unit) = add(encodeMap(block))

    internal fun encode() = CborRaw(bytesOf {
        writeHeader(4, size.toLong())
        out.writeTo(this)
    })
}

/** Already encoded CBOR, written as is. */
@JvmInline
value class CborRaw(val bytes: ByteArray)

private fun encodeMap(block: CborMapEncoder.() -> Unit) =
    CborRaw(bytesOf { writeMap(CborMapEncoder().apply(block).entries) })

private fun encodeArray(block: CborArrayEncoder.() -> Unit) = CborArrayEncoder().apply(block).encode()

private fun encodeValue(value: Any?): ByteArray = bytesOf { writeValue(value) }

private inline fun bytesOf(block: ByteArrayOutputStream.() -> Unit): ByteArray =
    ByteArrayOutputStream().apply(block).toByteArray()

private fun ByteArrayOutputStream.writeValue(value: Any?) {
    when (value) {
        null -> write(0xF6)
        is Boolean -> write(if (value) 0xF5 else 0xF4)
        is Int -> writeInteger(value.toLong())
        is Long -> writeInteger(value)
        is String -> writeBytes(3, value.toByteArray(Charsets.UTF_8))
        is ByteArray -> writeBytes(2, value)
        is CborRaw -> write(value.bytes)
        is List<*> -> {
            writeHeader(4, value.size.toLong())
            value.forEach { writeValue(it) }
        }
        is Map<*, *> -> writeMap(value.map { (k, v) -> Pair(encodeValue(k), encodeValue(v)) })
        else -> throw IllegalArgumentException("Unsupported: ${value::class}")
    }
}

private fun ByteArrayOutputStream.writeInteger(value: Long) {
    if (value >= 0) writeHeader(0, value) else writeHeader(1, -1 - value)
}

private fun ByteArrayOutputStream.writeBytes(major: Int, bytes: ByteArray) {
    writeHeader(major, bytes.size.toLong())
    write(bytes)
}

/** Writes a map with its keys in CTAP2 canonical order. */
private fun ByteArrayOutputStream.writeMap(entries: List<Pair<ByteArray, ByteArray>>) {
    writeHeader(5, entries.size.toLong())
    entries.sortedWith(compareBy(canonicalKeyOrder) { it.first }).forEach { (k, v) ->
        write(k)
        write(v)
    }
}

/** Shorter keys first, then bytewise lexicographic. */
private val canonicalKeyOrder = Comparator<ByteArray> { a, b ->
    if (a.size != b.size) return@Comparator a.size - b.size
    for (i in a.indices) {
        val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
        if (d != 0) return@Comparator d
    }
    0
}

/** [value] must not be negative. */
private fun ByteArrayOutputStream.writeHeader(major: Int, value: Long) {
    val type = major shl 5
    if (value < 24) return write(type or value.toInt())
    val (info, size) = when {
        value < 0x100 -> 24 to 1
        value < 0x10000 -> 25 to 2
        value < 0x100000000 -> 26 to 4
        else -> 27 to 8
    }
    write(type or info)
    for (i in size - 1 downTo 0) write((value shr (8 * i)).toInt())
}

// ============================================================

class CborDecoder private constructor(private val data: ByteArray) {
    private var pos = 0

    companion object {
        fun decode(data: ByteArray): Any? = CborDecoder(data).readValue()

        /**
         * Measure how many bytes the first CBOR value in the data occupies.
         */
        fun measureFirstValue(data: ByteArray): Int {
            val decoder = CborDecoder(data)
            decoder.readValue()
            return decoder.pos
        }
    }

    private fun readValue(): Any? {
        require(remaining > 0) { "Unexpected end of CBOR input" }

        val initial = data[pos++].toInt() and 0xFF
        val major = initial shr 5
        val info = initial and 0x1F

        if (major == 7) return readSimpleValue(info)

        val argument = readArgument(info)
        return when (major) {
            0 -> argument
            1 -> -1L - argument
            2 -> readByteString(argument)
            3 -> readTextString(argument)
            4 -> readArray(argument)
            5 -> readMap(argument)
            else -> null
        }
    }

    private fun readSimpleValue(info: Int): Any? = when (info) {
        20 -> false
        21 -> true
        else -> null
    }

    private fun readArgument(info: Int): Long {
        val size = when (info) {
            in 0..23 -> return info.toLong()
            24 -> 1
            25 -> 2
            26 -> 4
            27 -> 8
            else -> return 0L
        }
        require(size <= remaining) { "CBOR argument of $size bytes doesn't fit in $remaining bytes" }
        val value = (pos until pos + size).fold(0L) { acc, i -> (acc shl 8) or (data[i].toLong() and 0xFF) }
        pos += size
        return value
    }

    private val remaining get() = data.size - pos

    private fun readByteString(length: Long): ByteArray {
        require(length in 0..remaining) { "CBOR byte string of ${length.toULong()} bytes doesn't fit in $remaining bytes" }
        val len = length.toInt()
        val result = data.sliceArray(pos until pos + len)
        pos += len
        return result
    }

    private fun readTextString(length: Long): String {
        require(length in 0..remaining) { "CBOR text string of ${length.toULong()} bytes doesn't fit in $remaining bytes" }
        val len = length.toInt()
        val result = String(data, pos, len, Charsets.UTF_8)
        pos += len
        return result
    }

    private fun readArray(length: Long): List<Any?> {
        require(length in 0..remaining) { "CBOR array of ${length.toULong()} items doesn't fit in $remaining bytes" }
        val len = length.toInt()
        return List(len) { readValue() }
    }

    private fun readMap(length: Long): Map<Any?, Any?> {
        require(length in 0..remaining / 2) { "CBOR map of ${length.toULong()} entries doesn't fit in $remaining bytes" }
        val len = length.toInt()
        val result = LinkedHashMap<Any?, Any?>(len)
        repeat(len) {
            val key = readValue()
            val value = readValue()
            result[key] = value
        }
        return result
    }
}

class CborMap(private val raw: Map<Any?, Any?>) {

    companion object {
        fun decode(data: ByteArray): CborMap? {
            val decoded = CborDecoder.decode(data) as? Map<*, *> ?: return null
            @Suppress("UNCHECKED_CAST")
            return CborMap(decoded as Map<Any?, Any?>)
        }
    }

    operator fun get(key: Int): Any? = raw[key.toLong()] ?: raw[key]
    operator fun get(key: String): Any? = raw[key]

    fun int(key: Int): Int? = (this[key] as? Number)?.toInt()
    fun int(key: String): Int? = (this[key] as? Number)?.toInt()

    fun long(key: Int): Long? = (this[key] as? Number)?.toLong()
    fun long(key: String): Long? = (this[key] as? Number)?.toLong()

    fun bool(key: Int): Boolean? = this[key] as? Boolean
    fun bool(key: String): Boolean? = this[key] as? Boolean

    fun string(key: Int): String? = this[key] as? String
    fun string(key: String): String? = this[key] as? String

    fun bytes(key: Int): ByteArray? = this[key] as? ByteArray
    fun bytes(key: String): ByteArray? = this[key] as? ByteArray

    fun map(key: Int): CborMap? = (this[key] as? Map<*, *>)?.let {
        @Suppress("UNCHECKED_CAST")
        CborMap(it as Map<Any?, Any?>)
    }
    fun map(key: String): CborMap? = (this[key] as? Map<*, *>)?.let {
        @Suppress("UNCHECKED_CAST")
        CborMap(it as Map<Any?, Any?>)
    }

    fun <T> list(key: Int): List<T>? {
        @Suppress("UNCHECKED_CAST")
        return this[key] as? List<T>
    }
    fun <T> list(key: String): List<T>? {
        @Suppress("UNCHECKED_CAST")
        return this[key] as? List<T>
    }

    fun mapList(key: Int): List<CborMap>? = list<Map<Any?, Any?>>(key)?.map { CborMap(it) }
    fun mapList(key: String): List<CborMap>? = list<Map<Any?, Any?>>(key)?.map { CborMap(it) }

    fun containsKey(key: Int): Boolean = raw.containsKey(key.toLong()) || raw.containsKey(key)
    fun containsKey(key: String): Boolean = raw.containsKey(key)
}

fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }

fun String.hexToByteArray(): ByteArray {
    val len = length
    val out = ByteArray(len / 2)
    for (i in 0 until len step 2) {
        out[i / 2] = ((Character.digit(this[i], 16) shl 4) + Character.digit(this[i + 1], 16)).toByte()
    }
    return out
}
