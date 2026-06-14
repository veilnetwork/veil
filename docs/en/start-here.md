# Start Here — Veil in Plain Language

New to Veil? This page explains what it is, why it exists, and every word you'll
run into — no prior knowledge assumed. If a term ever looks scary, it's spelled
out in the **[Glossary](#the-words-youll-see-glossary)** below.

## What is Veil, really?

Think about sending a message to a friend. Normally it travels through some
company's servers: your phone → their data center → your friend. That company
can read who-talks-to-whom, can go offline, and can be ordered to block you.

Veil takes the company out of the middle. Instead of central servers, the
network is made of many equal participants — called **nodes** — all running the
same program. Your message hops from node to node until it reaches your friend.
There's no head office to subpoena and no single switch to flip off.

Two things make that worth the trouble:

- **It resists censorship.** Even if your internet provider tries to block Veil,
  the traffic can be disguised to look like ordinary web browsing, so it's hard
  to spot and hard to block.
- **It's private.** Messages are sealed end to end — only you and your friend
  can read them. The nodes that pass a message along see only scrambled bytes.

You don't have to trust any company. You just run a node — or use an app that
runs one for you.

## If there's no server, how does it find my friend?

Two simple ideas do the heavy lifting:

1. **Addresses are math, not places.** Your friend's address isn't an IP or a
   phone number — it's computed from their cryptographic key (a long, unique
   number only they control). It stays the same no matter where they connect
   from.
2. **A shared address book.** All the nodes together keep a distributed
   directory (the **DHT**) that maps an address to "here's where to reach them
   right now." No single node holds the whole book — everyone keeps a slice.

## The words you'll see (Glossary)

You don't need to memorize these. Come back whenever one trips you up.

- **Node** — one running copy of Veil. It's your seat at the table: it connects,
  passes traffic along, and stores things for the network. Run one and you *are*
  part of Veil.
- **Peer** — another node that yours is talking to directly. Your neighbors on
  the network.
- **Identity** — your node's cryptographic "passport": a pair of keys (a public
  one everyone may see, and a private one only you hold). Your address is built
  from it. Lose the private key and you lose the identity — so back it up.
- **Address (node_id)** — a node's unique name, computed from its public key. It
  doesn't depend on your IP or location.
- **Relay** — a node that forwards a message it isn't the final recipient of —
  like a postal sorting office passing your letter onward.
- **Transport** — *how* the bytes physically travel: plain TCP, encrypted TLS,
  QUIC, a WebSocket, and so on. Veil can switch between them — and add new ones —
  without changing anything else.
- **Obfuscation** — dressing the traffic up to look like something ordinary
  (say, a normal HTTPS website) so a censor watching the wire can't tell it's
  Veil.
- **End-to-end encryption** — only the sender and the final recipient can read
  the content. The relays in between carry a sealed envelope they can't open.
- **DHT** — the network's shared, distributed address book (formally a *Kademlia
  distributed hash table*), used to find where a node is right now.
- **Bootstrap** — how a brand-new node finds its very first peers so it can join
  at all (using a built-in starter list, or an invite someone hands you).
- **Leaf vs. relay (client vs. server)** — a *leaf* sits behind your home router,
  reaches out, and isn't publicly reachable — perfect for a phone or laptop. A
  *relay* has a public address others can connect to and bootstrap from — a
  server you run, e.g. on a rented host.
- **Proof of Work** — a small math puzzle a node solves to create an identity.
  It costs a sliver of CPU time, which makes churning out fake identities
  expensive for spammers and cheap for honest users.

## Your first ten minutes

1. **Install** the `veil-cli` program — one command, no developer tools needed.
   See **[Install](install.md)**.
2. **Create your identity and config:**
   ```sh
   veil-cli config init
   ```
   This mints your key pair (your "passport") and writes a config file. Keep the
   resulting files safe — they *are* your identity.
3. **Start your node:**
   ```sh
   veil-cli node run
   ```
   It connects to the network and keeps running in the background.
4. **Check it's alive:**
   ```sh
   veil-cli node show
   ```
   You'll see your address, how long it's been up, and the peers you've found.
5. **Stop it** when you're done:
   ```sh
   veil-cli node stop
   ```

That's the whole loop — you're now a node on the network.

## Common questions

**Do I need a server?**
No. A laptop or phone works fine as a *leaf*. You only need a public *relay* if
you want to help other people join.

**Is it anonymous?**
It's *private* — content is end-to-end encrypted and your address isn't tied to
your IP — and traffic can be *obfuscated* against censorship. True anonymity
depends on how you set it up and use it; the **[OpSec guide](opsec-user-guide.md)**
walks through the trade-offs.

**What if my country blocks it?**
Veil's transports can mimic ordinary HTTPS and use bridges/invites that aren't
listed publicly, so there's nothing obvious for a censor to block. See the
server setup in **[Install](install.md)** for running a censorship-resistant
relay.

**I lost my keys — can I get back in?**
Only if you backed them up. See **[Recovery](recovery.md)** and
**[Multi-device](multi-device.md)**.

## Where to go next

- **[Install](install.md)** — get the prebuilt binaries.
- **[User guide](user-guide.md)** — the everyday commands.
- **[How it works](HOW_IT_WORKS.md)** — the technical tour, once the words above
  feel comfortable.
