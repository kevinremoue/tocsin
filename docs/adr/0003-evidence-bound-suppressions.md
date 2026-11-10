# Suppressions bind to evidence, not release labels or vulnerability names

A suppression accepts an exact set of matched versioned purls and material advisory applicability, not a project-wide exception. Changed evidence or a confirmed disappearance invalidates that acceptance, retaining the analysis rationale pending revalidation; cosmetic identity, severity and EPSS changes alone do not. Existing suppressions migrate without accepted evidence because assuming their scope would silently accept risk.

Only successful relevant matching can establish absence. Incomplete matching must qualify last-known evidence rather than claim safety. An actionable episode starts when a finding returns from absence or suppression: each alert rule can notify once in that episode, without reopening on threshold oscillations or component changes while actionable. Delivery retries can duplicate messages; exactly-once external delivery is not promised.
