package pl.lebihan.authnkey

/** Renders a getInfo response as indented plain text. */
fun DeviceInfo.dump(): String = buildDump {
    list("versions", versions)
    list("extensions", extensions)
    field("aaguid", aaguid)
    field("firmwareVersion", firmwareVersion)

    section("options") {
        options.forEach { (option, supported) -> field(option, supported) }
    }

    list("transports", transports.map { it.value })
    list("pinUvAuthProtocols", pinUvAuthProtocols)

    section("algorithms") {
        algorithms.forEach { item(it.dumpLine()) }
    }

    field("uvModality", uvModality)
    list("uvMethods", uvMethods.map { it.name })

    field("maxMsgSize", maxMsgSize)
    field("maxCredentialCountInList", maxCredentialCountInList)
    field("maxCredentialIdLength", maxCredentialIdLength)
    field("minPINLength", minPinLength)
}

private fun AlgorithmInfo.dumpLine(): String = listOfNotNull(
    type,
    alg?.id?.toString(),
    alg?.name?.let { "($it)" },
).joinToString(" ")

private fun buildDump(body: Dump.() -> Unit): String =
    Dump().apply(body).lines.joinToString("\n")

/** Collects lines, two spaces of indent per enclosing section. */
private class Dump {
    val lines = mutableListOf<String>()

    fun line(value: String) {
        lines += value
    }

    /** Writes `name: value`, or nothing when the value is absent. */
    fun field(name: String, value: Any?) {
        value?.let { line("$name: $it") }
    }

    /** Writes `name:` and an indented block, or nothing if the block is empty. */
    fun section(name: String, body: Dump.() -> Unit) {
        val nested = Dump().apply(body)
        if (nested.lines.isEmpty()) return
        line("$name:")
        nested.lines.forEach { lines += "  $it" }
    }

    /** Writes one `- value` line. */
    fun item(value: String) {
        line("- $value")
    }

    /** Writes `name:` and one line per entry. */
    fun list(name: String, values: Collection<Any>) {
        section(name) {
            values.forEach { item(it.toString()) }
        }
    }
}
