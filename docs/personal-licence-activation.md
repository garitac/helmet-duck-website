# Helmet Duck Personal: activating your licence

Thank you for buying a Personal licence. This file is the download attached to
your purchase; the licence key itself is in your receipt email and on your
Lemon Squeezy "My Orders" page.

1. Install Helmet Duck in Claude Code if you have not yet:

       /plugin marketplace add garitac/helmet-duck
       /plugin install helmet-duck@helmet-duck

2. Read the risks page, https://helmetduck.com/risks.html, then from a terminal:

       duck accept
       duck seal

3. Activate the key on this machine. The key may be activated on up to three
   machines. This is the only network call Helmet Duck ever makes, and only
   because you asked for it:

       duck licence activate YOUR-KEY-HERE

4. Confirm:

       duck licence status
       duck status

To move the licence to another machine, run `duck licence deactivate` on the
old one first. Support: https://github.com/garitac/helmet-duck. Terms:
https://helmetduck.com/terms.html.
