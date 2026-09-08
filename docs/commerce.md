# Money: sponsorship, licences, invoices

Approved 2026-09-06. Three channels, none of which runs code on this site.
The site links out; the counterparties collect the money and the data.

| Channel | For | Who is the seller | Fees | Tax handling | Status |
| --- | --- | --- | --- | --- | --- |
| GitHub Sponsors | Contributions | GitHub pays you; a gift, not a sale | 0% on personal sponsorships | Income to you; no VAT | Listing not yet enabled |
| Lemon Squeezy | Personal tier licence keys | Lemon Squeezy, as merchant of record | About 5% + 50¢, ~7.5% effective for a non-US seller | They register and remit foreign VAT and sales tax | Store not yet created |
| Stripe Invoicing | Team licences, for a Japanese company that needs a domestic invoice | You, in yen | Stripe's card or bank-transfer fee | Domestic consumption tax as for any business invoice | Stripe account exists and worked in sandbox; live verification to confirm |

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

## 3. The Team tier is a licence, not a service (owner)

The Team tier is one licence for up to ten machines and nothing else: no
installation, no custom gate, no hours. One person in Japan cannot promise time to
companies anywhere in the world, and the page says so (decided 2026-09-07). Sell it
through Lemon Squeezy like Personal, as a second product or as a quantity. A
Japanese company that needs a domestic invoice in yen can be sent one from the
existing Stripe account instead: card or bank transfer, domestic tax, no merchant
of record; live-mode verification in the Stripe dashboard is the one precondition.
Either way the sale carries no obligation of anyone's time.

## 4. Legal pages

| Page | State |
| --- | --- |
| `site/privacy.html` | Written; publishes with the next deploy |
| `site/terms.html` | Written; publishes with the next deploy |
| Commercial transactions disclosure (Act on Specified Commercial Transactions) | Template only, in `docs/legal/`. Needed only for sales where you are the seller to a consumer. Personal and Team licences are sold by the merchant of record, which carries the seller's obligations; invoices to companies are business transactions, which the Act does not cover. Confirm with a lawyer before the first direct consumer sale; until then the page, and your address on it, stay unpublished |
| `site/risks.html` and `RISKS.md` in garitac/helmet-duck-bushido | Written; acceptance is recorded by `duck accept` and arms the gates |

## 5. What was deliberately not done

- KANJI-SHOP was not ported. It is a physical-goods store for Japan with
  inventory reservations and JP-only shipping; the licence problem it does not
  solve is foreign tax and key delivery, which the merchant of record solves.
- No email for helmetduck.com. Contact is the GitHub profile until MX records
  exist; the disclosure page needs a decision here.
- No payment code on this site or in this repository, on purpose.
