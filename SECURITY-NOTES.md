# Log4Shell (CVE-2021-44228) — Security Notes

**Scope for the briefing:** exact facts on the Log4Shell RCE vulnerability, the remediation versions, and where the evidence comes from.

**CVE ID:** CVE-2021-44228 (Log4Shell) — GitHub Advisory Database record **GHSA-jfh8-c2jp-5v3q**.

**Severity:** **Critical** — NIST NVD CVSS 3.1 base score **10.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`). CISA's own advisory entry also rates it 10.0 Critical; note vendor variants that publish the scope-Unchanged variant at 9.8 — the briefing baseline is 10.0.

**Affected versions (log4j-core, the only directly affected artifact):**
`org.apache.logging.log4j:log4j-core` **>= 2.0-beta9**, **< 2.15.0**
- Broadly: **Apache Log4j 2.0-beta9 through 2.14.1**
- Java 6 branch: **>= 2.0-beta9, < 2.3.1**
- Non-default configurations matter: many separately-published patch tiers exist (2.12.2, 2.12.3, 2.3.1, etc.). Every tier below 2.15.0 is exposed.

**Fixed / patched versions:**
- **2.15.0** is the first release addressing CVE-2021-44228.
- Official guidance recommends **2.16.0** (Java 8+) and **2.12.2** (Java 7): the 2.15.0 fix was incomplete in some non-default configurations and follow-on JNDI injection remained possible through the message lookup substitution path. Plan the upgrade at **2.16.0+** and keep log4j-api versioned with log4j-core.
- Where no upgrade path is possible, mitigation and patch are temporary-only controls (see remediation issue #4).

**Exclusions / caveats:**
- Only `log4j-core` is directly affected. `log4j-api` is **not** vulnerable — patching only the API file does nothing.
- `log4j.net` and `log4j.cxx` are **not** impacted (per the GitHub Advisory Database).
- Log4j 1.x is End-of-Life and carries its own unrelated RCE vectors; it is not the version being patched.
- Upgrading Java alone is insufficient — the Log4j library itself must be upgraded.

## Remediation summary
1. Upgrade log4j-core to **2.16.0+** (Java 8) / **2.12.2** / **2.3.2** (Java 6) and pair the API with it. Log4j 1.x → full migration.
2. **Detect first:** grep logs and request surfaces for `${jndi:` (and encoded/obfuscated variants such as `${${lower:j}${lower:n}${lower:d}i:}` and `%24%7B`), watch outbound LDAP (389/636), RMI (1099), and JNDI-related DNS, and enumerate stacks against CISA's log4j-affected-db.
3. **Harden while patching is in flight:** delete or rename `JndiLookup.class` from the classpath; apply vendor hot patches if there is no change window; block JNDI/LDAP/RMI/DNS egress at the WAF/firewall/network-monitoring layer.
4. **Automate:** run dependency scanning in CI (OWASP Dependency-Track / Dependency-Check / Trivy / Snyk-tier scanners) with release gates on high/critical CVEs; add Dependabot alerts.

## Sources
- https://github.com/advisories/GHSA-jfh8-c2jp-5v3q (GitHub Advisory Database)
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228 (National Vulnerability Database)
- https://www.cisa.gov/sites/default/files/publications/AA21-356A_Joint_CSA_Mitigating_Log4Shell_and_Other_Log4j-Related_Vulnerabilities.pdf (CISA / Joint NSA-CISA-DIB advisory)
- https://www.cisa.gov/news-events/alerts/2021/12/10/apache-releases-log4j-version-2150-address-critical-rce-vulnerability-under-exploitation (CISA alert)
- https://logging.apache.org/log4j/2.x/security.html (Apache Logging Services official security page)
