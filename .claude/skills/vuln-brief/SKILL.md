---
name: "vuln-brief"
description: "Turn a vulnerability announcement or CVE ID into a fact-checked writeup, a mitigation runbook, and a FUD score. Use when a new branded or high-profile vuln drops."
---

# Vuln brief

Input: a CVE ID, a branded name, a researcher write-up URL, a vendor advisory, or Steven's own draft. A brand often covers several CVEs (PHP2Shell is CVE-2026-109618 and CVE-2026-109619): find every CVE under it, research each, and roll up to the highest rung. Note which CVE attackers are actually hitting, because it may not be the one in the headline. Output: one Docs artifact with three tabs (Writeup, Mitigation runbook, Fact-check), plus a FUD score. If a draft is supplied, keep its voice and structure and correct it. Don't rewrite it from scratch.

The default audience is SMB peers (120-500 seats) who don't have time to research. Enterprise output is the same pipeline with the SMB filter off and the full runbook as the main deliverable.

## 0. Expand to the whole advisory

Never brief only the CVEs you were handed. Read each CVE record's vendor-advisory reference and pull in every CVE that shares it, from a local cvelistV5 clone (`fud_meter.py --cvelist-dir`) or the advisory itself. Then check KEV for every sibling. In the SonicWall SNWLID-2026-0014 case, the three CVEs asked about were rung 0, and the KEV-listed SAML bypass (CVE-2026-19868, scored lower at 7.1) was a sibling in the same advisory. The brief leads with whichever sibling sets the rung, not with the highest CVSS.

## 1. Gather primary sources (fetch, never rely on snippets)

- Researcher write-up (trigger, affected configs, demo targets, exploit release status, timeline).
- CNA or vendor advisory and its risk matrix (score, vector, affected builds).
- Upstream project advisory if different (for example OpenJDK, Apache, kernel).
- CVE JSON 5: `https://cveawg.mitre.org/api/cve/<ID>`. Read the CNA metrics and the ADP containers: CISA SSVC (Exploitation, Automatable, Technical Impact), KEV flag, CWE, and supplier ADPs (for example Siemens SADP) that list bundled products.
- EPSS: `https://api.first.org/data/v1/epss?cve=<ID>` (score, percentile, date).
- CISA KEV feed.
- One or two secondary reports only to fill gaps when a primary page won't load. Label them as secondary.

NVD is not the backbone. Since April 2026 it enriches only priority CVEs.

## 2. Claim ledger (the Fact-check tab)

One table row per claim: draft said | sources say | source link | change made. Always check:

- Version ranges, including the lower bound. Bugs often start mid-line (for example 17.0.6+).
- Trigger or precondition variants per version.
- Attack surfaces the headline skipped (client side, agents, outbound connections).
- Score disagreements. Name the yardstick: CVSS 3.1 vs 4.0, CNA vs researcher.
- In-the-wild status, from SSVC and KEV, not from press.
- Vendor numbering vs upstream numbering for fixed builds, and distro backports that fix a bug without changing the upstream version string.
- Execution context that changes exploitability (for example PHP mod_php vs PHP-FPM, Java server vs client).

When credible sources contradict each other (one sees successful exploitation, another sees only failed attempts), add a "Sources disagree" row naming both, and carry the disagreement into the writeup rather than picking a side.

Add a "Not verified" list for anything that came from secondary sources or memory, and a dated "Signals" list (EPSS, KEV, SSVC).

## 3. FUD meter (goes at the top of the writeup)

Place the vuln on the highest rung whose evidence is met. No weighted sums: every rung must be explainable in one line and one source.

| Rung | Label | Line | Evidence required |
| --- | --- | --- | --- |
| 0 | Theoretical | This never had a PoC because it's too theoretical. | Nothing public, and researchers or the vendor describe it as impractical |
| 0 | No public details yet | Vendor-confirmed, details withheld. Nobody has shown it working in public. | Nothing public, but the vendor confirmed it and shipped a fix. Use this label by default; "Theoretical" only when someone actually says it's impractical |
| 1 | Proof of concept | Someone made it crash or corrupt memory. Nobody has shown it doing harm. | Public crash or corruption PoC, or SSVC exploitation: poc |
| 2 | Demonstrated | Researchers showed real impact on real products. Exploits not public. | Credible researcher demo of impact on named products |
| 3 | Weaponized | Working exploit code is public. Assume scanning starts this week. | Public working exploit (Metasploit, ExploitDB, Nuclei template, GitHub verified) |
| 4 | Exploited | Confirmed exploitation in the wild. | CISA KEV, SSVC exploitation: active, or vendor confirms |
| 5 | Mass targeting | The best time to patch this was days ago, so go do it now. | Rung 4 plus KEV ransomware use, or a scanning feed showing mass targeting (GreyNoise, CDN or WAF reports). EPSS 99th percentile+ is a proxy only and is labeled as one until a scanning feed confirms it |

Don't read SSVC "Automatable: no" as evidence against rung 5. It describes the exploit chain, not attacker behavior: PHP2Shell was marked not automatable while public kits were mass-scanning the internet.

Also show what evidence would move it up one rung, and the EPSS percentile as context.

Headline noise is a side readout, never part of the rung: brand name, logo or site, famous-bug comparison, absolute language, 15+ articles in 72h, researcher score a point or more above the CNA. Loud at rung 2 or below gets the callout "Headlines run ahead of the evidence." Quiet at rung 3 or above gets "Quiet for how real it is."

When inventory exposure is known (none, internal, internet), give an action window. Defaults: rung 5 means hours if internet-facing and 24h if internal; rung 4 means 24h and 72h; rung 3 means 72h and 7d; rung 2 means 7d and 30d; rungs 0 to 1 follow the normal cycle. If fud_meter.py is available, run it instead of placing the rung by hand.

**Edge-device floor.** For internet-facing edge gear (firewalls, VPNs, remote-access appliances, file-transfer servers) from a vendor with one or more CISA KEV entries in the last 12 months, use at least the rung-2 action window, whatever this bug's rung. Count the vendor's KEV entries from the feed (`vendorProject`, `dateAdded`) and state the count in the brief.

**CVSS provenance.** Record whose score you're quoting: CNA, CISA ADP, or researcher. If the CNA gave none, say so. In the SonicWall case the 8.8 scores the press repeated were CISA's, and they required user interaction.

Never use the rung or the noise to skip patching. They set the window and the tone.

## 3a. SMB filter and publish decision

Run this right after the meter, before writing anything.

**SMB relevance:**
- **yes:** the product is in a typical SMB stack: Windows and M365, browsers, edge firewalls and VPNs (Fortinet, SonicWall, WatchGuard, Meraki, Sophos, Palo Alto), RMM and remote access (NinjaOne, ConnectWise, ScreenConnect, Kaseya, Datto, N-able, TeamViewer, AnyDesk), backup and NAS (Veeam, Synology, QNAP), WordPress and PHP hosting, QuickBooks and common line-of-business apps, ESXi and Hyper-V.
- **indirect:** it reaches SMBs through a hosting provider, an MSP, or a runtime bundled in a vendor appliance.
- **no:** enterprise or developer infrastructure (Kafka, Gerrit, Spinnaker, self-hosted Artifactory).

**Publish:**
- **Fleet hit overrides everything:** if the inventory match finds the component in a client environment, it's SMB-relevant. Rung 3 or higher gets an action brief; rung 2 or lower gets a **validation brief** (confirm the patch or workaround on every hit, and record whether each clear is durable or conditional).
- **Action brief:** SMB-relevant (yes or indirect) and rung 3 or higher.
- **Calm-down brief:** SMB-relevant, rung 2 or lower, loud headlines. Owners forward these headlines and ask "are we affected?", so this brief has real value.
- **Log only:** quiet and rung 2 or lower, or not SMB-relevant (goes to the enterprise queue).

**Review tag:**
- **Hold for review** when the claim ledger has a "Sources disagree" row, or any fact in the brief rests on a secondary source. These are where automation is most likely to be confidently wrong.
- **Everything else may ship tagged Unreviewed.**

If fud_meter.py is available, it prints the relevance, the publish decision, and the hold reasons.

## 4. Writeup tab (Steven's voice)

- Open by saying whether it's real, in one or two sentences, with the trigger in plain terms.
- Who's affected, pre-auth vs post-auth, and that the list is incomplete if the researcher says so.
- "It isn't another <famous bug>" paragraph when the headline noise is loud and the rung is 2 or below, backed by SSVC and exploit status. When the noise is loud and the rung is 4 or 5, say plainly that the hype is earned.
- Reconcile the scores in one short paragraph: why both numbers can be right.
- "Most of you can narrow your exposure fast": bullets for CPU or platform, versions, distributions, and a note on who still patches anyway.
- The detail that makes it nastier than it sounds, if there is one.
- Patch first, then workarounds with exact flags or config and their caveats, then priority products, then bundled or embedded copies.
- Fake-PoC warning whenever weaponized exploits are withheld, and whenever branded tools are circulating that may not use the real bug.
- Dry closing line. Numbered references, cited inline as [n].
- Short declarative sentences, no hype words, no emoji.

## 5. Mitigation runbook tab

1. Gates table: each precondition, when it's open, when it's reduced, when it's closed, how to check. "Reduced" covers partial mitigations and less-exploitable configurations (for example `memory_limit=-1` for PHP2Shell, or PHP-FPM instead of mod_php). A reduced gate never clears a host; it drops it one priority tier.
2. Check commands per OS, including VMs (hypervisor CPU masking), containers, and bundled runtimes.
3. Ask the software itself where possible (for example `java -XX:+PrintFlagsFinal`, `jcmd <pid> VM.flags`), and check live processes, not just binaries on disk.
4. Patch: vendor numbering caveat, bundled copies, restart requirement.
5. Workarounds: preferred option first, with its cost; a product-by-product table of where the setting goes, marked "confirm against vendor docs".
6. Priority tiers P1 to P4 plus Clear, driven by the gates and exposure (internet-facing, pre-auth product, outbound-only).
7. Detection: published IOCs, or honest "none published" plus crash and log signals labeled by strength.

## 6. Applicability rule (feeds the inventory match)

Alongside the two docs, emit `applicability.json`, the machine-readable version of the runbook's gates:

- Software: vendor, product, affected ranges per line (with minimum affected build), fixed build per vendor where known, special-case builds.
- Platform: architecture, OS, CPU features (and a model fallback list for inventories that don't report flags).
- Config: settings that open, reduce, or close the path (for example workaround flags, server mode, memory limits). Inventory rarely reports these, so they usually need a collector.
- Version matching: list distro backport sources (Debian, Ubuntu, RHEL security trackers). A version string below the upstream fix on a distro build is "possible", not "affected", until the distro tracker is checked.
- Exposure weights: pre-auth products, post-auth products, client-side or outbound conditions.
- Blind spots: where standard inventory will miss copies (bundled runtimes, container images, appliances). Matches there go to a "possible, needs collector" bucket, never to Clear.

Mark the rule "draft, needs review". A wrong rule silently clears exposed assets, so a person signs off before it runs against client inventory. The matcher itself is deterministic (j4s_triage.py pattern): same engine, new rule.

## 6a. Quick brief (the SMB deliverable)

One screen, written so the reader needs no research. It becomes the doc's first tab; the full writeup, runbook, and fact-check follow as later tabs.

1. **Meter line:** rung, label, and its one-line quote.
2. **Review tag, directly under the meter line, as a banner:** "Reviewed by Steven, <date>" or "Unreviewed: machine-generated from primary sources. Verify before acting." Forwarded copies lose context, so the tag sits in the body, never in a footnote.
3. **What we're doing:** one or two sentences in the frame "It's your call, but here's what we're doing:", followed by Steven's actual decision and window. Peers short on time copy the default, so it must be a real, specific decision, never generic advice. A draft brief carries a proposed position marked "(Proposed position, for Steven to confirm.)"; the review step settles it and removes the marker. For a calm-down brief, the decision is the deferral plus its tripwire ("Normal patch cycle; we move it to 72 hours if it lands on KEV").
4. **Are you affected?** Three yes/no checks in plain words ("Do you run your own WordPress server, or does a host run it?").
5. **What to do, by situation:** you run it; your provider or host runs it (what to ask them); it's inside a vendor appliance (which advisory to watch).
6. **When:** the action window. For a calm-down brief, say plainly why it's lower priority and what would change that (the next rung's evidence).
7. **Link to the full runbook.**

Plain words, no jargon the owner of a 150-seat company wouldn't know, no more than about 250 words.

## 7. Deliver

Create the doc first with pending sections, open it, fill one section per call, then give the link and the FUD line in chat. In the chat reply, include the publish decision and the review tag, and list the hold reasons if it's held. Keep the rest to the verdict and anything the reader must decide.