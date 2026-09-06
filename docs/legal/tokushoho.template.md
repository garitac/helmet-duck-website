# 特定商取引法に基づく表記 — template, NOT published

Japanese law (特定商取引法) requires a seller offering goods or services online to
publish these items before the first sale. Digital licences count. Fill every
placeholder, have it checked, then publish it as `site/legal/tokushoho.html`
and link it from the footer. Until then it stays here, out of `site/`, so the
build cannot publish placeholders by accident.

| 項目 | 内容 |
| --- | --- |
| 販売事業者名 | Carlos Garita（屋号があれば併記） |
| 運営責任者 | Carlos Garita |
| 所在地 | 【住所。個人事業主は請求があれば遅滞なく開示する旨の記載で省略可】 |
| 電話番号 | 【電話番号。同上の省略規定を使う場合はその旨】 |
| 連絡先 | 【メールアドレス。helmetduck.com の受信設定が必要】 |
| 販売価格 | 各商品ページに表示（税込） |
| 商品代金以外の必要料金 | なし（通信費は購入者負担） |
| 支払方法 | クレジットカード等（決済代行事業者を購入時に表示） |
| 支払時期 | 購入手続き完了時 |
| 商品の引渡時期 | 決済完了後、ライセンスキーを直ちに電子的に交付 |
| 返品・キャンセル | デジタル商品の性質上、交付後の返品・返金は原則不可。決済代行事業者の規定が優先する場合はその旨 |
| 動作環境 | Python 3.9 以降、Claude Code（Codex 対応は後続版） |

Notes for the owner:
- The address and phone may be omitted for an individual seller only if the page
  states they will be disclosed without delay on request. Decide which.
- Email requires MX records for helmetduck.com; none exist today. Until they
  do, a GitHub contact is the only working channel and must be named here.
- Consumption tax treatment on prices is your accountant's call; the merchant
  of record handles foreign buyers' taxes, not Japanese 消費税 on domestic sales.
