# sick-call

**Daily vulnerability triage for SMB defenders. What needs you today, and what can wait.**

Every named bug shows up at sick call claiming to be dying. Most go back to duty with Motrin and water. A few need the medevac. sick-call is how we tell them apart, in writing, before the peer group chat catches fire.

Patching everything, every time, the moment it's announced is no longer a plan. sick-call puts each advisory on a six-rung ladder built only from evidence, says plainly what we're doing about it, and watches the ones we defer so "not today" never turns into "forgot."

> **Status: v0.1 alpha.** The ladder works and the backtest is published, misses included. Briefs are drafted by hand with the skill and reviewed before they go out. Expect the ladder and file formats to change before 1.0; the [changelog](CHANGELOG.md) will say when.

## The ladder

A vulnerability sits on the highest rung whose evidence is met. No weighted scores: every rung traces to one source you can check.

| Rung | Label | What we tell you | Evidence |
| --- | --- | --- | --- |
| 0 | No public details yet | Vendor-confirmed, details withheld. Nobody has shown it working in public. | Vendor advisory and fix, nothing public |
| 0 | Theoretical | This never had a PoC because it's too theoretical. | Researchers or vendor call it impractical |
| 1 | Proof of concept | Someone made it crash or corrupt memory. Nobody has shown it doing harm. | Public crash PoC, or CISA SSVC exploitation: poc |
| 2 | Demonstrated | Researchers showed real impact on real products. Exploits not public. | Credible demo on named products |
| 3 | Weaponized | Working exploit code is public. Assume scanning starts this week. | Metasploit, ExploitDB, Nuclei, verified PoC |
| 4 | Exploited | Confirmed exploitation in the wild. | CISA KEV, SSVC active, or vendor confirms |
| 5 | Mass targeting | The best time to patch this was days ago, so go do it now. | Rung 4 plus ransomware use or mass scanning |

Two rules sit beside the ladder:

- **Headline noise never moves the rung.** Loud coverage on a low rung gets called out. Quiet coverage on a high rung gets called out too.
- **Edge-device floor.** Internet-facing firewalls, VPNs, and remote-access gear from a vendor on CISA KEV in the last 12 months get at least the rung-2 window, whatever the rung.

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

Briefs are keyed by **advisory**, not CVE. The exploited bug is often the quiet sibling of the one in the headlines.

## The Binnacle List

Everything that comes through sick call lands on the **Binnacle List**: each advisory, its rung, its window, what we're doing about it, and the tripwire that would move it. It comes in two forms:

- **The live list:** the current open and deferred advisories, kept in the repo and updated whenever the watch list runs.
- **The weekly digest:** everything that came through sick call that week, in one place.

### Why the name

As a corpsman with a Marine battalion, I oversaw sick call every morning and then updated the binnacle list for battalion and company leadership, outlining who was down, for how long, and if they were confined to quarters or light duty. Leadership didn't need clinical detail, they needed to know who was out and how it impacted the plan of the day.

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

There are three ways in, and most people only need the first.

1. **Read the briefs.** Follow the repo or the feed. No install, no data shared.
2. **Run it yourself.** Clone the repo and run the meter, collectors, and inventory match on infrastructure you maintain: a VM, your RMM, or a self-hosted runner. Client data stays in your environment and never comes back here.
3. **Contribute back.** Applicability rules, new regression cases, and fixes are welcome as pull requests. Fleet data, hostnames, and client names are not.

### Local configuration

The built-in product list is a wide SMB baseline, so it works out of the box. Tune it to your client base without editing code:

```
cp sick-call.example.json sick-call.local.json
```

`sick-call.local.json` is git-ignored, so `git pull` keeps bringing in updates without merge conflicts. You can set:

| Setting | What it does |
| --- | --- |
| `publisher` | Your MSP's name and reviewer, used on briefs you publish |
| `smb_products_add`, `smb_products_remove` | Adjust which products count as SMB-relevant for your clients |
| `edge_words_add` | Add edge gear you support that the baseline misses |
| `windows` | Your SLAs per rung: three values (no exposure, internal, internet-facing) from the supported list |
| `edge_floor` | Turn the edge-device floor on or off, or change its threshold and floor rung |
| `panic_cvss` | The CVSS score your peers treat as drop-everything, for the backtest's "panic avoided" count |

Config changes your windows, relevance, and labels. It never changes a rung, because rungs come only from evidence. To check against the baseline, run with `SICK_CALL_CONFIG=none`, which is what the tests do.

### The "What we're doing" line belongs to the publisher

Every brief carries a "What we're doing" line, and in this repo it's sick-call's position. If you republish a brief to your own clients, replace that line with your own decision. CC BY 4.0 requires attribution to sick-call. It doesn't make our position yours, and your clients deserve to know whose call it is.

## Roadmap

| Version | What ships | Done when |
| --- | --- | --- |
| **0.1 alpha** | Ladder, backtest results, three regression cases, hand-drafted briefs | Backtest scorecard published with its misses |
| 0.2 | Daily intake and watch list in GitHub Actions, no LLM; the live Binnacle List | Two quiet weeks of intake output that look right |
| 0.3 | Drafting via pull requests; review gate and held labels in CI | First automated brief merged after review |
| 0.4 | RSS feed, webhooks, weekly Binnacle List digest | Peers get briefs without visiting the repo |
| 1.0 | Stable ladder and formats | 90 days of live briefs, scored the same way as the backtest |

## What's not here

No client data, ever. Inventory matches and fleet exposure stay in private tooling and reach a brief only as an exposure level.

## License

- **Code** (`tools/`, `backtest/`, `tests/`): [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0). Use it anywhere, including inside your own RMM scripts and tooling. Keep the `NOTICE` file with it.
- **Briefs, writeups, runbooks, the ladder, and docs** (`briefs/`, `README.md`, `.claude/skills/`): [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Share and adapt them; credit sick-call.

The full license texts live in `LICENSE` (Apache-2.0) and `LICENSE-CONTENT` (CC BY 4.0).
