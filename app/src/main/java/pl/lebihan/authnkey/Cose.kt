package pl.lebihan.authnkey

/** A COSE algorithm identifier, as listed in the IANA COSE Algorithms registry. */
@JvmInline
value class CoseAlgorithm(val id: Int) {

    /** The registered name, or null if the identifier is not one we know. */
    val name: String?
        get() = when (id) {
            -7 -> "ES256"
            -8 -> "EdDSA"
            -35 -> "ES384"
            -36 -> "ES512"
            -37 -> "PS256"
            -38 -> "PS384"
            -39 -> "PS512"
            -47 -> "ES256K"
            -257 -> "RS256"
            -258 -> "RS384"
            -259 -> "RS512"
            -65535 -> "RS1"
            else -> null
        }
}
