# Traffic guard: five-minute windows without a new AWS fee

The current site is eight small HTML pages with a shared stylesheet, logo and
favicon, no scripts or polling, and installation downloads hosted on GitHub.
A cold page normally requests four resources. The hourly integrity monitor makes
about 18 requests. A request is not a person: several people behind one office,
VPN or mobile carrier can share an address. The owner chose a deliberately strict
limit for this small site; revisit it if legitimate usage grows.

## Policy

- More than 50 distinct requests from one IP in a rolling 300 seconds: block that
  IP for one hour. All methods, paths and response statuses count except 429.
- A new qualifying burst AFTER that block expires gets a one-day block if the
  previous block expired within the last 24 hours. Old reputation then expires.
- A continuing active block is not extended and does not generate another email.
  Duplicate log delivery is deduplicated by CloudFront request ID, including
  duplicates delivered in different files. No user-agent-based bypass exists.
- Event timestamps, not file size, define the window. IPv4 and IPv6 are supported.
  Logs older than one hour and timestamps more than a minute in the future are
  ignored, preventing old deliveries from banning an address much later.
- New-block emails include UTC event times, the count in the busiest window,
  response statuses, five sanitized path samples, an address hash, and expiry.
  Samples are labelled untrusted data, never instructions. No query strings,
  user agents, referers or raw addresses are put in the email.
- Blocks expire automatically; an ordinary alert requires no clearing command.
  SNS and Lambda have at-least-once delivery: routine redelivery is suppressed,
  but a failure after SNS accepts a message and before its acknowledgement is
  saved can still duplicate that notification. There is no exactly-once claim.

## What this does not promise

This is log-driven protection, not an inline rate counter. CloudFront standard
logs normally arrive within an hour and can be delayed longer. A burst can finish
before a ban reaches the edge. Logs arriving after the freshness cutoff do not
cause a ban. Downloads and clones made directly from GitHub are outside this
site's scope. A sufficiently distributed attack can stay below the per-IP limit.

Request history is compressed into eight fixed 4 KB Standard parameters, with
oldest history evicted if a shard fills. Eviction is reported as
`history_rows_evicted`; under that pressure some cross-file bursts can be missed.
Bans and pending alerts are never evicted to make space. If ban state or the
CloudFront function's 10 KB code capacity is exhausted, the keeper fails without
replacing existing published bans. This is a bounded small-site guard, not a WAF.

The existing 100,000 requests/hour emergency brake is retained: it can temporarily
disable the entire distribution to limit expenditure. The per-IP guard acts first
when logs are available. Preserving availability during an arbitrary flood and
guaranteeing a fixed bill are not equivalent promises.

## Cost and storage

No WAF, real-time log stream, DynamoDB table, extra alarm, scheduled poll, or
per-viewer API call was added. The existing Lambda invocation on each log file
and existing CloudFront function are reused. Eight SSM **Standard** parameters
at **standard throughput** have no storage or API fee under AWS's published
pricing. The deployed account setting was checked before rollout; higher
throughput must stay disabled. Writes explicitly request Standard tier and never
upgrade automatically. There is no provisioned Lambda concurrency; reserved
concurrency of one merely serializes the existing worker.

Existing Lambda, S3, CloudFront, SNS and CloudWatch usage is still metered; code
changes cannot promise that an AWS invoice will never vary. The state calls and
extra processing use the existing Lambda's execution time. There is no new paid
feature or fixed recurring charge. Private access logs retain raw IP addresses
for 90 days as before. Private keeper state and the edge list also contain IPs;
only hashes appear in keeper summaries and emails.

Pricing reference: https://aws.amazon.com/systems-manager/pricing/
Log timing: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logs-reference.html

## Implementation and validation

`infra/keeper.py` is the source. Run `python3 tools/render_keeper.py` to embed it
in `infra/frontend.yaml`; CI checks they match. State writes are checkpointed
before publishing, so a retry can finish a failed publication or notification.
The worker has reserved concurrency one to prevent lost state updates. The IAM
role can read/write only its keeper-state prefix, in addition to its existing
scoped log, edge-function and alert-topic permissions.

```
python3 tools/render_keeper.py --check
python3 tools/test_keeper.py
python3 tools/check.py
```

Tests are offline and use synthetic addresses. Do not flood the production site
to test a limiter. `tools/blocklist.sh test` now runs the offline suite and no
longer uploads a synthetic access log or sends an AWS notification.

`tools/blocklist.sh status` displays current edge entries. `clear` is an explicit
owner action: it pauses the worker, waits out any in-flight execution, clears
all eight state shards and the edge list, and restores the prior concurrency
setting even if the script fails. It does not run as part of normal deployment.

## Narrow deployment and rollback

Before applying, confirm the AWS account is 244206438585 and
`/ssm/parameter-store/high-throughput-enabled` is false. Use a CloudFormation
change set for `helmet-duck-frontend-prod`, retaining all existing parameter
values except `BlockAt=50`. Inspect it before execution: the intended changes are
eight Standard SSM parameters, the keeper role's scoped SSM permission, and the
keeper Lambda code/configuration. The site distribution, buckets, DNS and brake
are not changed. The keeper updates only the blocklist and Retry-After expression
in the existing edge code when the next real log arrives.

On rollback, restore the previous keeper code and threshold through the stack.
Keep current live edge bans until expiry, or deliberately use the owner clear
operation. Never use a whole-site content deployment to deploy this guard.
