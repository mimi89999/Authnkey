package pl.lebihan.authnkey

import pl.lebihan.etldx.InvalidDomainNameException
import pl.lebihan.etldx.PublicSuffixList

/** An rpId split into the parts we order by. Both parts are already lower cased. */
private class DomainKey(val registrable: String, val subdomain: String)

private fun PublicSuffixList.keyFor(rpId: String): DomainKey =
    try {
        val domain = split(rpId)
        // registrableDomain is null when the rpId is a public suffix itself
        DomainKey(domain.registrableDomain ?: domain.name, domain.subdomain.orEmpty())
    } catch (_: InvalidDomainNameException) {
        // The RP registered something that is not a domain name.
        DomainKey(rpId.lowercase(), "")
    }

/**
 * Orders credentials by registrable domain, then by subdomain, then by user name.
 *
 * Sorting on the eTLD+1 keeps `example.com`, `login.example.com` and `account.example.com` together
 * under E instead of scattering them across the list.
 */
fun List<CredentialItem>.sortedByRegistrableDomain(psl: PublicSuffixList): List<CredentialItem> {
    val keys = map { it.rpId }.distinct().associateWith(psl::keyFor)
    return sortedWith(
        compareBy<CredentialItem> { keys.getValue(it.rpId).registrable }
            .thenBy { keys.getValue(it.rpId).subdomain }
            .thenBy(String.CASE_INSENSITIVE_ORDER) {
                it.credential.userName ?: it.credential.userDisplayName ?: ""
            }
    )
}
