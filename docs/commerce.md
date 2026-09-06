# Money: sponsorship, licences, invoices

Approved 2026-09-06. Three channels, none of which runs code on this site.
The site links out; the counterparties collect the money and the data.

| Channel | For | Who is the seller | Fees | Tax handling | Status |
| --- | --- | --- | --- | --- | --- |
| GitHub Sponsors | Contributions | GitHub pays you; a gift, not a sale | 0% on personal sponsorships | Income to you; no VAT | Listing not yet enabled |
| Lemon Squeezy | Personal tier licence keys | Lemon Squeezy, as merchant of record | About 5% + 50¢, ~7.5% effective for a non-US seller | They register and remit foreign VAT and sales tax | Store not yet created |
| Stripe Invoicing | Team tier, Japanese companies | You, in yen | Stripe's card or bank-transfer fee | Domestic consumption tax as for any business invoice | Stripe account exists and worked in sandbox; live verification to confirm |

## 1. GitHub Sponsors (owner, about 15 minutes)

1. Open https://github.com/sponsors/garitac/dashboard and complete the listing:
   identity, country Japan, bank details through Stripe Connect.
2. Add two tiers: a small monthly one and a one-time "buy the duck a helmet".
   The text can be the same sentence the site uses.
3. Publish the listing. The repository already carries `.github/FUNDING.yml`,
   so the Sponsor button appears on its own, and the site's Support section
   links to the same page. Deploy the site once the listing is live; before that
   the link lands on an empty page.

## 2. Lemon Squeezy (owner, about 30 minutes)

1. Create the store, country Japan, payout bank.
2. Product "Helmet Duck Personal", one variant, one-time payment, price of your
   choosing in USD (they convert). Enable **License keys** on the variant with
   an activation limit (3 machines is a fair default) and no expiry.
3. Copy the variant's checkout URL into `site/index.html`, Personal tier button.
   Replace "Price to be announced" with the price. Publish the commercial
   transactions disclosure first (`docs/legal/commercial-transactions-disclosure.template.md`).
4. Buyers run `duck licence activate <KEY>`. The duck calls Lemon Squeezy's
   License API once, records the instance locally, and shows the tier in
   `duck status`. Nothing in version 0.1 is gated behind it; the record is the
   beginning of the paid tier, not a lock. Gating, when it comes, is a
   deliberate, announced change.

Why Lemon Squeezy rather than Paddle: both are merchants of record; only Lemon
Squeezy issues licence keys natively, and the duck's `licence` command speaks
its API. Paddle would mean building key issuance yourself.

## 3. Stripe Invoicing for the Team tier (owner)

The Team tier is installation, a custom gate and half a day with you, sold to a
Japanese company. Send a Stripe invoice in yen from the existing Stripe account;
the buyer pays by card or bank transfer. Domestic sale, domestic tax, no
merchant of record needed. Live-mode verification in the Stripe dashboard is the
one precondition; you confirmed the account worked in sandbox.

## 4. Legal pages

| Page | State |
| --- | --- |
| `site/privacy.html` | Written; publishes with the next deploy |
| `site/terms.html` | Written; publishes with the next deploy |
| Commercial transactions disclosure (Act on Specified Commercial Transactions) | Template only, in `docs/legal/`; needs your address decision and a contact channel; publish before the first sale |
| `site/risks.html` and `RISKS.md` | Written; acceptance is recorded by `duck accept` and arms the gates |

## 5. What was deliberately not done

- KANJI-SHOP was not ported. It is a physical-goods store for Japan with
  inventory reservations and JP-only shipping; the licence problem it does not
  solve is foreign tax and key delivery, which the merchant of record solves.
- No email for helmetduck.com. Contact is the GitHub profile until MX records
  exist; the disclosure page needs a decision here.
- No payment code on this site or in this repository, on purpose.
