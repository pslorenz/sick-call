# sick-call

**Daily vulnerability triage for SMB defenders. What needs you today, and what can wait.**

> Fix what is reachable, exploited, and holding the keys first. Everything else goes on a schedule you can defend in writing.

Every named bug shows up at sick call claiming to be dying. Most go back to duty with Motrin and water. A few need extra care. sick-call is how we tell the vulnerabilities apart, in writing, before the group chat catches fire.

Patching everything, every time, the moment it's announced is no longer a plan. sick-call puts each advisory on a six-rung ladder built only from evidence, says plainly what we're doing about it, and watches the ones we defer so "not today" never turns into "forgot."

> **Status: v0.1 alpha.** The ladder works and the backtest is published, misses included. Briefs are drafted by hand with the skill and reviewed before they go out. Expect the ladder and file formats to change before 1.0; the [changelog](CHANGELOG.md) should map.

## The ladder

**sick-call triages; it isn't incident response.** The ladder weighs evidence of exploitation *elsewhere*. If you have credible signs of compromise in your own environment, stop reading briefs and activate your incident response plan.

A vulnerability sits on the highest rung whose evidence is met. No weighted scores: every rung traces to one source you can check.

| Rung | Label | What we tell you | Evidence |
| --- | --- | --- | --- |
| 0 | No public details yet, *or* Theoretical | Vendor-confirmed, details withheld. Nobody has shown it working in public. *Or, when someone says it's impractical:* this never had a PoC because it's too theoretical. | Nothing public. "Theoretical" only when researchers or the vendor call it impractical |
| 1 | Proof of concept | Someone made it crash or corrupt memory. Nobody has shown it doing harm. | Public crash PoC, or CISA SSVC exploitation: poc |
| 2 | Demonstrated | Researchers showed real impact on real products. Exploits not public. | Credible demo on named products |
| 3 | Weaponized | Working exploit code is public. Assume scanning starts this week. | Metasploit, ExploitDB, Nuclei, verified PoC |
| 4 | Exploited | Confirmed exploitation in the wild. | CISA KEV, SSVC active, or vendor confirms |
| 5 | Mass targeting | The best time to patch this was days ago, so go do it now. | Rung 4 plus ransomware use or mass scanning |

Two rules sit beside the ladder:

- **Headline noise never moves the rung.** Loud coverage on a low rung gets called out. Quiet coverage on a high rung gets called out too.
- **Edge-device floor.** Internet-facing firewalls, VPNs, and routers get at least the rung-2 window (7 days), whatever the rung. An earlier version only applied this to vendors with recent CISA KEV entries; the backtest showed MikroTik slipping past that condition and landing on KEV 5 days after disclosure.
- **Remote-access floor.** Internet-facing remote access and RMM tools (ScreenConnect, Kaseya VSA, TeamViewer, AnyDesk and the like) always get at least the rung-3 window (72 hours). They are the way into every client an MSP manages, and the backtest found ScreenConnect going from disclosure to KEV in 3 days.

## Action windows (internet-facing / internal)

| Rung | Internet-facing | Internal |
| --- | --- | --- |
| 5 | Hours | 24 hours |
| 4 | 24 hours | 72 hours |
| 3 | 72 hours | 7 days |
| 2 | 7 days | 30 days |
| 0-1 | Normal patch cycle | Normal patch cycle |

Deferred items go on the watch list. If the evidence moves up a rung, the window moves with it.

## What a brief looks like

One screen, written so you don't have to do the research:

1. The rung and its one-line verdict.
2. A review tag: **Reviewed** by a named person, or **Unreviewed**, machine-generated from primary sources.
3. **What we're doing.** It's your call, but here's ours, with a real decision and a window.
4. Are you affected? Three yes/no checks.
5. What to do if you run it, if your provider runs it, or if it's buried in a vendor appliance.
6. When.
7. A link to the full runbook and fact-check.

Everything gets scored; the SMB filter only decides what gets a brief. Dropped advisories still leave a log record, so a later fleet hit can pull them back in. To brief something the filter dropped, run it manually:

```
python3 tools/fud_meter.py briefs/2026/<advisory>/signals.json --requested "Your Name"
```

Briefs are keyed by **advisory**, not CVE. The exploited bug is often the quiet sibling of the one in the headlines. Vendors that ship on a schedule (Microsoft, Adobe, Oracle, Chrome, Mozilla) get one advisory per release: a Patch Tuesday is one brief, led by the few CVEs that are actually being exploited.

## The Binnacle List

Everything that comes through sick call lands on the **Binnacle List**: each advisory, its rung, its window, what we're doing about it, and the tripwire that would move it. It comes in two forms:

- **The live list:** the current open and deferred advisories, kept in the repo and updated whenever the watch list runs.
- **The weekly digest:** everything that came through sick call that week, in one place.

### Why the name

As a corpsman that spent some time with a Marine battalion, I oversaw sick call every morning and then updated the binnacle list for battalion and company leadership, outlining who was down, for how long, and if they were confined to quarters or light duty. Leadership didn't need clinical detail, they needed to know who was out and how it impacted the plan of the day.

That is the intended purpose here, sick call is the triage and the Binnacle List is what goes to leadership and program runners afterward. The name comes from the ship's binnacle, the stand that holds the compass, where the list was posted for the officer of the deck. The Binnacle List represents a navigational aid with regard to vulnerability prioritization.

In the files it's plain `watchlist.json`, so contributors don't have to decode anything. "Binnacle List" is the name readers see.

## Repository layout

```
briefs/YYYY/<advisory-id>/   brief, writeup, runbook, fact-check, meter snapshots, applicability rule
cases/                       judgment calls we made once; tests make sure rule changes don't flip them
backtest/                    scores the ladder against past disclosures
tools/fud_meter.py           the ladder, SMB filter, publish rule
tools/collectors/            deep checks for things inventory can't see (CPU features, bundled runtimes)
watchlist.json               deferred advisories and their tripwires (published as the Binnacle List)
sick-call.example.json       template for your git-ignored sick-call.local.json
.claude/skills/vuln-brief/   the drafting workflow
```

## Results

The v0.1 backtest scored 90 days of disclosures (2026-08-23 to 2026-11-21) as if sick-call had been running on day 0 of each one.

- **1,434** SMB-relevant advisories. **28** were exploited before their window closed. The ladder called **23** of those urgent on the day they dropped.
- The other **5** were all internet-facing systems the business runs itself, and all hit CISA KEV within **3 to 10 days**. None escalated after its window closed.
- **112** SMB-relevant bugs scored CVSS 9.0+ were deferred, stayed quiet for 30+ days, and were never exploited.
- EPSS gave no early warning on the misses. The watch list did the work.

The full scorecard, the five misses, the workload it puts on an MSP, and the limits are in [backtest/RESULTS-v0.1.md](backtest/RESULTS-v0.1.md).

## Run the backtest

```
git clone --depth 1 https://github.com/CVEProject/cvelistV5
git clone https://github.com/projectdiscovery/nuclei-templates      # full history: template dates matter
curl -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

python3 backtest/backtest.py --cvelist cvelistV5 --kev kev.json --nuclei nuclei-templates --epss --days 90
```

Signals are rebuilt as of each advisory's disclosure day, so nothing learned later leaks in. The backtest uses feed evidence only, so its rungs are the automated floor; a human reading the researcher's write-up can only raise them. Results land in `backtest/out/`.

## Tests

```
python3 -m unittest discover -s tests -t .
```

## Using sick-call at your MSP

There are three ways:

1. **Read the briefs.** Follow the repo or the feed. No install, no data shared.
2. **Run it yourself.** Clone the repo and run the meter, collectors, and inventory match on infrastructure you maintain: a VM, your RMM, or a self-hosted runner. Client data stays in your environment and never comes back here.
3. **Contribute back.** Applicability rules, new regression cases, and fixes are welcome as pull requests. Fleet data, hostnames, and client names are not.

### Local configuration

The built-in baseline is wide, and it's anchored to vendors: a product only counts if it comes from the vendor that makes it, so "Acme Agent for Windows" isn't Windows and a WooCommerce add-on isn't WooCommerce. Works out of the box, tune it to your client base without editing code:

```
cp sick-call.example.json sick-call.local.json
```

`sick-call.local.json` is git-ignored, so `git pull` keeps bringing in updates without merge conflicts. You can set:

| Setting | What it does |
| --- | --- |
| `publisher` | Your MSP's name and reviewer, used on briefs you publish |
| `smb_vendors_add` | Add vendors your clients run, with the products that count (`[]` means all of that vendor's products) |
| `smb_products_add`, `smb_products_remove` | Add product keywords that count for any vendor, or drop baseline entries (vendors or keywords) |
| `edge_words_add` | Add edge gear you support that the baseline misses |
| `windows` | Your SLAs per rung: three values (no exposure, internal, internet-facing) from the supported list |
| `release_groups` | Group a scheduled vendor's CVEs into one advisory per release, by CNA: `month`, `day`, or `none` to switch it off |
| `remote_access_floor` | Turn the remote-access floor on or off, or change its floor rung |
| `edge_floor` | Turn the edge-device floor on or off, or change its threshold and floor rung |
| `panic_cvss` | The CVSS score your peers treat as drop-everything, for the backtest's "panic avoided" count |

Config changes your windows, relevance, and labels. It never changes a rung, because rungs come only from evidence. To check against the baseline, run with `SICK_CALL_CONFIG=none`.

### The "What we're doing" line belongs to the publisher

Every brief carries a "What we're doing" line, and in this repo it's sick-call's position (and not an actual MSP, we're as in the maintainer). If you republish a brief to your own clients, replace or augment that line with your own decision(s). CC BY 4.0 requires attribution to sick-call. It doesn't make the maintainer's position yours, and your clients deserve to know whose call it is.

## Roadmap

| Version | What ships | Done when |
| --- | --- | --- |
| **0.1 alpha** | Ladder, backtest results, three regression cases, hand-drafted briefs | Backtest scorecard published with its misses |
| 0.2 | Daily intake and watch list in GitHub Actions, no LLM; the live Binnacle List; `recheck_by`, `owner`, and `expires` on deferrals, workarounds, and conditional clears | Two quiet weeks of intake output that look right |
| 0.3 | Drafting via pull requests; review gate and held labels in CI | First automated brief merged after review |
| 0.4 | RSS feed, webhooks, weekly Binnacle List digest | Peers get briefs without visiting the repo |
| 1.0 | Stable ladder and formats | 90 days of live briefs, scored the same way as the backtest |

## What's not here

No client data, ever. Inventory matches and fleet exposure stay in private tooling and reach a brief only as an exposure level.

## License

- **Code** (`tools/`, `backtest/`, `tests/`): [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0). Use it anywhere, including inside your own RMM scripts and tooling. Keep the `NOTICE` file with it.
- **Briefs, writeups, runbooks, the ladder, and docs** (`briefs/`, `README.md`, `.claude/skills/`): [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Share and adapt them; credit sick-call.

The full license texts live in `LICENSE` (Apache-2.0) and `LICENSE-CONTENT` (CC BY 4.0).
