# Risks and mitigations

Version 0.2.0. Effective 2026-09-06. Published at https://helmetduck.com/risks.html and
shipped in this repository as `RISKS.md`. The two are the same text.

Helmet Duck runs as hooks inside your coding agent's harness, with your user
privileges, on your machine. Read this page before installing it. Installing,
running, or keeping Helmet Duck installed means you have read this page and
accept every risk on it. The duck refuses nothing until you have recorded that
acceptance with `duck accept`. The author, Carlos Garita, accepts none of these
risks on your behalf.

## What it can and cannot do to your system

- It can refuse an action your agent attempts through the Bash, Write or Edit
  tools, stop a turn from ending, and add text to the agent's context.
- It cannot run commands of its own, modify your files, delete anything, or make
  an agent do anything. It only refuses, advises and records.
- It writes only under `~/.helmet-duck`. Its only network connection is a
  licence activation that you start yourself with `duck licence activate`.

## The risks

| # | Risk | What happens | Mitigation | What you accept |
| --- | --- | --- | --- | --- |
| 1 | A false refusal | A legitimate action is refused: an overwrite of a file the duck did not see you read, a command that matches a known-bad pattern, a commit without fresh evidence. | Every refusal names its gate and the way out in one fixed sentence. `duck override` opens every gate for 30 minutes. Uninstalling removes everything. | Friction, and the time to read the refusal. |
| 2 | Fail-closed on a defect | If the duck itself crashes, or its file no longer matches its sealed manifest, it refuses every Bash, Write and Edit until you override or uninstall. This is the one way it can truly stop an agent. | Deliberate: a broken guard must not become a silent allow. The selftest runs before every release. The override and uninstall always work. | A stopped agent, never a damaged system. |
| 3 | Missed catches | It does not see a claim an agent makes in prose, a write whose path is assembled at runtime inside another program, or a defect shape it has no pattern for. The mirror's recall is partial. | Stated here and in every report the duck prints. | You must not rely on Helmet Duck as a guarantee that an agent behaves. It reduces some failures; it prevents none with certainty. |
| 4 | Turn-end blocking | The turn cannot end while claims are open in the ledger. | Capped at two blocks in a row, then allowed and logged. It cannot loop. | Two extra turns at most. |
| 5 | Latency | About 100 milliseconds are added to each tool call. | Measured under 150 milliseconds in the selftest on ordinary hardware. | Slower tool calls. |
| 6 | Reading your transcripts | The mirror reads every transcript your agent harness keeps on this machine, for every project, to count the moments the machine caught the agent. | Everything stays under `~/.helmet-duck`. Nothing is transmitted. You can disable the SessionStart hook or delete the mirror's files. | That a plugin reads local transcripts that may contain your other work. |
| 7 | Influence of injected text | The duck adds the Agent Code and dissent questions to the agent's context. Any text in context can change what an agent does. The Code tells the agent to deliver and to wait for the owner's word on irreversible acts; the duck cannot enforce how a model reads it. | The text is short, fixed, English only, and visible in this repository. The dissent chair never denies; it only asks. | That an agent may act on, ignore, or misread advisory text, and that the outcome is the agent's and yours. |
| 8 | Interaction with other hooks and plugins | Other hooks may allow what the duck refuses, or refuse what it allows. Order and combined outcomes depend on your harness. | The duck's decisions are logged with their reasons under `~/.helmet-duck/log.jsonl`. | Diagnosing conflicts yourself. |
| 9 | Updates from the author's repository | New versions arrive through the plugin marketplace when the author bumps the version. A compromised or defective release would run on your machine with your privileges. | Inspect the diff before updating; the source is visible for exactly that reason. The seal detects tampering on your machine, not a bad upstream. | The same supply-chain risk as any plugin you install. |
| 10 | Licence activation | Activating a paid licence sends the key and a label for your machine to the merchant of record, once. | The call is made only when you run the command. The answer is stored locally with restricted permissions. | That the merchant learns which machine activated a key. |
| 11 | Work interrupted at a bad moment | A refused commit or an interrupted turn can leave you with uncommitted changes. | Nothing is deleted by the duck, ever. The override exists for exactly this moment. | Finishing the step yourself. |
| 12 | Wrong or outdated documentation | This page, the README and the site may lag behind the code. | The code is the authority; every claim here names the mechanism you can read. | Reading the code when it matters. |
| 13 | Modified copies | Anyone can edit the source. A modified duck may refuse the wrong things, refuse nothing, or do harm the original cannot. | A sealed duck fails closed when its file no longer matches its manifest, so a modified copy announces itself. The author distributes only through the repository named on this site. | A modified copy is not Helmet Duck. Whoever modified it owns everything it does; the author is not liable for it. |
| 14 | Installation on a system you do not own | Helmet Duck reads transcripts and refuses actions on whatever machine it is installed on, with that machine's user privileges. Installing it on someone else's system, or without the authority to do so, is a decision the installer makes. | Acceptance is recorded per user on the machine, with the user name, version and time. | Whoever installs it is solely responsible for having the authority to do so and for that system's owner; the author is not liable to the installer, to the system's owner, or to anyone affected. |

## What you must do

1. Read this page.
2. Install, then run `duck accept`. Until then the duck records and refuses nothing.
3. Keep `duck override` in mind. It is the way out of any refusal.
4. Report a defect with the exact refusal text and the command that was refused.
5. Uninstall if you disagree with anything here. Deleting `~/.helmet-duck` removes every record it kept.

## Liability and acceptance

Helmet Duck is provided as is, without warranty of any kind, express or
implied, including fitness for a particular purpose and non-infringement. By
installing or using it you accept the risks on this page. To the fullest extent
permitted by applicable law, Carlos Garita is not liable for any loss, damage,
cost or claim arising from Helmet Duck, from its refusals or its failures to
refuse, or from any action of an agent, whether that action was refused,
allowed, influenced or missed by Helmet Duck. Where the law does not permit an
exclusion, liability is limited to the amount you paid for Helmet Duck in the
twelve months before the claim, which for the free tier is nothing.

The author is likewise not liable for any copy that anyone has modified, for
any copy obtained other than from the repository named on this site, or for any
installation made by a person who did not own the system or lacked the
authority to install software on it. Whoever modifies Helmet Duck, redistributes
it, or installs it on a system they do not own is solely responsible for the
consequences and for any claim by that system's owner or by anyone affected,
and agrees to hold Carlos Garita harmless from such claims. These terms are
governed by the laws of Japan. The full terms are at
https://helmetduck.com/terms.html.
