# Log4Shell (CVE-2021-44228) — Security Notes

**Status:** Verified as Critical. **Staging** hold before reunion.

**CVE ID:** CVE-2021-44228 (Log4Shell) — GitHub Advisory Database record `GHSA-jfh8-c2jp-5v3q`.

**Affected versions:**
`org.apache.logging.log4j:log4j-core` `>= 2.0-beta9`, `< 2.15.0`
(2.3.1 / 2.12.2 / 2.12.3 / 2.3.1 / 2.0 / 2.3.1 — approximate range)

**Fixed / patched versions:**
`org.apache.logging.log4j:log4j-core 2.15.0+`

**Severity:** **Critical** — NIST NVD CVSS 3.1 base score **10.0** (`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`).
**CISA / Apache:** also rated Critical. (Note: NVD's GitHub-reviewed entry carries
scope-Changed `CVSS:3.1/.../S:C/C:H/I:H/A:H` = 10.0 Critical; some vendors record
`S:U` variant, i.e. 9.8.)

**Key technical facts:**
- `log4j-api` is **not** vulnerable; only the `log4j-core` artifact is affected.
- Only the `log4j` logging service touches user data; `log4j2` / `log4jnet` are unaffected.
- CVE-2021-45046 (Patchlink) was a follow-on CVSS 9.0 Critical deviation in 2.15.0 missing the recursive path in message lookup substitution.
- CVE-2021-45105 is rated 9.8 Critical (PoC released Jan 2022).

**Remediation summary:**
1. Upgrade log4j-core to 2.17.1+ (Java 8), 2.12.4 (Java 7), 2.3.2 (Java 6). (CVE-2021-45105 is rated 9.8 Critical (PoC released Jan 2022).)
2. Enable `log4j2.formatMsgNoLookups=true` and application-message reduction pre-2.15.0 temporary mitigations.
3. Remove `JndiLookup.class` from the class path and block JNDI on LDAP/RMI/DNS/nis objects at the WAF/firewall/NMFG layer.
4. Add automated dependency scanning / CSP protection level.

## Sources
- https://github.com/advisories/GHSA-jfh8-c2jp-5v3q (GitHub Advisory Database)
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228 (National Vulnerability Database)
- https://www.cisa.gov/sites/default/files/publications/AA21-356A_Joint_CSA_Mitigating_Log4Shell_and_Other_Log4j-Related_Vulnerabilities.pdf (CISA/Joint CSA)
- https://www.cisa.gov/news-events/alerts/2021/12/10/apache-releases-log4j-version-2150-address-critical-rce-vulnerability-under-exploitation (CISA alert)
- https://logging.apache.org/log4j/2.x/security.html (Apache Logging Services official security page)
