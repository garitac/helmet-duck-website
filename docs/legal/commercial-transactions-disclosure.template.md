# Commercial transactions disclosure (Japan) — template, NOT published

Japanese law, the Act on Specified Commercial Transactions, requires a seller
offering goods or services online to publish these items before the first
sale. Digital licences count. Fill every placeholder, have it checked, then
publish it as `site/legal/disclosure.html` and link it from the footer. Until
then it stays here, out of `site/`, so the build cannot publish placeholders by
accident. English is the language of this site; a lawyer may advise adding a
Japanese version.

| Item | Content |
| --- | --- |
| Seller | Carlos Garita (add the trade name if one is registered) |
| Person responsible | Carlos Garita |
| Address | [Address. An individual seller may omit it if the page states it will be disclosed without delay on request.] |
| Telephone | [Number, or the same disclosure-on-request statement.] |
| Contact | [Email address. Requires mail setup for helmetduck.com, which does not exist yet.] |
| Prices | Shown on each product page, tax included |
| Charges beyond the price | None; connection costs are the buyer's |
| Payment methods | Card and other methods offered by the merchant of record, shown at checkout |
| Payment timing | At purchase |
| Delivery | The licence key is delivered electronically immediately after payment |
| Returns and cancellation | Digital goods: no return or refund after delivery as a rule; the merchant of record's refund policy, shown at checkout, governs where it applies |
| Operating environment | Python 3.9 or later; Claude Code, with Codex support in a later version |

Notes for the owner:
- The address and telephone may be omitted for an individual seller only if the
  page states they will be disclosed without delay on request. Decide which.
- Email requires MX records for helmetduck.com; none exist today. Until they do,
  the GitHub profile is the only working contact and must be named here.
- Consumption-tax treatment of prices is your accountant's decision. The
  merchant of record handles foreign buyers' taxes, not Japanese consumption
  tax on domestic sales.
