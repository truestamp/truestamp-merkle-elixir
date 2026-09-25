<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Truestamp.Merkle security model

What an inclusion proof from this library proves, what it does not prove, and the
decisions behind the checks in `Truestamp.Merkle`. Written for someone reviewing the
module, writing an independent verifier against it, or deciding what a proof is worth
inside a system of their own. The module's own `@moduledoc` carries the API contract; this
file carries the reasoning.

## Reporting a vulnerability

Do not open a public GitHub issue for a security report. Use one of these private channels:

1. **GitHub private vulnerability report** (preferred), at
   <https://github.com/truestamp/truestamp-merkle-elixir/security/advisories/new>.
2. **Email** to <security@truestamp.com>, with "truestamp-merkle-elixir" in the subject
   line.

Include a minimal reproduction where you can: the entries, the proof and the root, and what
you expected to happen. Only the latest commit on `main` is supported.

## What a proof attests

An inclusion proof is a claim about one 32-byte digest and one root:

> The leaf hash of this digest, SHA-256(0x00 || digest), was one of the leaves of the tree
> whose root is that root hash.

It establishes existence (the value was present when the tree was built) and integrity
(change one bit of the value, or one bit of any node on the path, and the recomputed root
no longer matches). `verify/4` recomputes the root from the value and the proof and
compares it with the root you supplied, so the proof is only as meaningful as your
confidence in that root. `walk/3` recomputes the same root and hands it back without being
given one.

The proof's `leaf_index` and `tree_size` add a second claim, that the value sat at that
position in a tree of that many entries, and that claim holds only when the size comes
from the same trusted place as the root. The root commits to the size, but a verifier
cannot read it out of the root, and the RFC 9162 walk never checks it. Most proofs still
reach the same root with `tree_size` raised by one (97% of all proofs in trees of 1 to 300
entries), though no tree of that size has that root, and the index can move with it: the
last of three entries also verifies as index 1 of a two-entry tree. Given the true size,
no other index verifies, unless another entry carries the same digest, in which case the
digest is at that index too. This is RFC 9162's design, not a defect of this library:
Certificate Transparency takes the size from the signed tree head that carries the root. A
verifier here takes it from the record that gives it the root, and never from the proof
alone.

Root distribution is outside this library. A proof and a root obtained from the same
party in the same response prove nothing about that party's honesty: they can build a
tree containing anything they like and hand you its root. The root has to reach the
verifier through a channel the verifier already trusts, and everything a root means beyond
"these leaves were in a tree" is a property of that channel rather than of the tree. Both
the channel and its guarantees are yours to build; this module supplies neither. Truestamp
is one worked example: it publishes each root in a hash-linked chain of blocks and commits
those block hashes to public blockchains, and that is where its roots acquire a time and
an independent witness.

## What a proof does not attest

**Not creation time.** A Merkle proof carries no time at all. Any timing claim comes from
the surrounding system, which has to establish independently when the leaf value existed
and when the root was published. The proof only ties one to the other. In Truestamp, for
instance, a metadata hash bound into the leaf value fixes the submitted-after edge of a
submission window, and the commitment of the block holding that leaf to public blockchains
fixes the submitted-before edge; the two together pin a submission window around the
leaf. Even then the claim is about submission, not
about when the underlying data came into existence.

**Not authorship.** Nothing about who submitted a value is hashed into a leaf. If you need
to attribute a value to a submitter, that binding has to be arranged upstream or carried
outside the proof entirely. Truestamp records authorship as `Item.creator_id`,
deliberately outside every hash.

**Not an append-only history.** RFC 9162 also defines consistency proofs between two
sizes of a log; this library implements only inclusion proofs. There are no consistency
proofs, no signed tree heads and no log monitoring, so none of the append-only guarantees
a Certificate Transparency log provides are available from this module. Tamper evidence
over time has to be built around the roots by the caller. Truestamp gets it from the block
hash chain and the public blockchain commitments.

**Not any binding between a key and a hash.** This is the one most likely to be assumed.
`verify/4` takes a digest, a proof and a root, and `walk/3` a digest and a proof.
There is no key argument, and there is no place to put one. `proof/2` takes a key, but
only to look up the entry's position; the key is never hashed into a leaf, an interior
node, or the root. Keys affect leaf *order* (`new/1` orders leaves by key, and a
different order would give a different root) and they are checked for uniqueness at
construction, but no proof ever carries evidence about which key a leaf was filed under.

**Not the order, and not absence.** Sorting by key is a rule the builder follows, not a
property a verifier can check: a root does not show that its entries were sorted, or that
it was built by this library at all. And there are no absence proofs: nothing here shows
that a key or a digest is not in a tree.

So a valid proof for hash `H` under root `R` says exactly that `H` was in that tree. It
does not say `H` belonged to record 42, or to account X, or to a document with a given
name. If your application needs that binding, commit the identifier into the digest
upstream, before the value reaches the tree. Truestamp is an example of how that looks in
practice: `item_hash` is a domain-separated composite over the record's id along with its
claims and metadata hashes, so the id is inside the value the proof is about. A system
that hands this library a bare content digest and stores the identifier alongside it in a
database has no cryptographic link between the two, and this library will not supply one.

## Hash construction and domain separation

Leaves and interior nodes are hashed in separate domains, as RFC 9162 section 2.1 (and
RFC 6962 before it) defines:

    leaf     = SHA-256(0x00 || digest)             digest is 32 bytes
    interior = SHA-256(0x01 || left || right)      left and right are 32 bytes each
    empty    = SHA-256("")                         root of a tree with no leaves

The prefix byte is the primary defense, and what it defends against is the classic
second-preimage attack on unprefixed Merkle trees. Without it, the 64-byte concatenation
`left || right` sitting under an interior node hashes to the same value as a 64-byte
"leaf" holding those same bytes, so anyone could present an interior node's children as a
leaf and produce a shorter valid-looking path to the root. With the prefix, a value that
was hashed as an interior node can never be reinterpreted as a leaf: verification hashes
the supplied value with `0x00`, an interior node was hashed with `0x01`, and the two
results differ. The test suite checks this on random trees: an interior node, presented as
a leaf with its own position, size and the path above it, reaches the root when walked as
a node and fails when verified as a leaf.

The 32-byte input check is secondary, defense in depth, and it should not be described as
what prevents interior-node forgery. It refuses a 64-byte value at the door rather than
letting it through to be rejected by the prefix rule, and it keeps the hash surface
uniform, but the domain separation is what makes the attack impossible rather than merely
inconvenient.

None of this is homegrown. The tree shape, the audit path and the verification loop are
RFC 9162 section 2.1's, so any implementation of that RFC or of RFC 6962 reproduces the
roots and accepts the proofs; the tests hold the library to the published known answers of
six Go implementations and to proofs from production logs (`vectors/interop/`). The only
thing this library adds is the order: entries are sorted by key before the digests become
the RFC's leaf data.

## Canonical hex

Every hash crossing the API as text is exactly 64 lowercase hex characters, on the way in
and on the way out: the digests you supply for entries, the root hashes you get back, the
digests being proved, and the nodes of a path alike. The binary form of a proof carries its
nodes as raw 32-byte values. Non-canonical input is refused, never
normalized. `new/1` raises `ArgumentError`; `walk/3` returns an error and `verify/4`
returns `false`.

Refusing rather than downcasing is deliberate. Two spellings of the same hash would be two
distinct strings in the tree's entries and in stored proofs, and a library that quietly
accepts both invites a caller to believe the spelling does not matter. The cost is that an
uppercase hash produces a `false` from `verify/4` that looks exactly like a proof that
does not check out; `walk/3` names the refusal instead. Hexdump tools commonly emit
uppercase, so downcase before calling rather than reading that `false` as a cryptographic
result.

The validators match a fixed 64-byte head and then decode it with `Base.decode16/2` in
lowercase mode, rather than matching a regular expression. That closes a real hole: PCRE's
`$` matches before a trailing newline, so a 64-hex hash with a `\n` appended would pass such
a pattern and then raise out of a decode deep inside verification, in a function documented
never to raise. A 65-byte value cannot match a 64-byte head, and the decode checks every
character and decodes in the same pass.

## What an observer can infer from a proof

A proof discloses more than the digest it proves. It states the tree's entry count and
the entry's position outright, as `tree_size` and `leaf_index`. Its first node is usually a
neighbouring entry's leaf hash, `SHA-256(0x00 || digest)`, so anyone holding a guess at that
neighbour's digest can confirm the guess. A higher node can be one too: when a level has an
odd number of nodes its last one moves up unchanged, so the last entry of a tree with an odd
count, for one, can appear in other entries' proofs as its own leaf hash. The other nodes
are hashes over two or more entries and confirm nothing without all of their digests.

Whether this matters is a question about your data, not about the tree. A digest that is
the hash of guessable content is exposed to that confirmation wherever it appears, in a
proof or not; one that is a composite including something unpredictable is not.
Truestamp's leaf values are composites of that kind (an item's leaf value includes its
ULID, which has random bits, and its entropy witnesses), and Truestamp shows each block's
counts of items and entropy observations, whose sum is its leaf count, on its explorer
anyway, so there a proof discloses what the front end states outright.

## Bounds, limits, and which entry points face untrusted input

`walk/3`, `verify/4` and `proof_from_binary/1` are the entry points safe to put in front of
untrusted callers. None of them raises on its input: only an invalid option raises.

`walk/3` and `verify/4` check the value being proved, then the proof's shape and ranges
(its path must be a list), then that the index is below the size, then the path length the
index and size require against the step cap, and only then the path itself. That length is
at most 64, since `tree_size` is at most 2^64 - 1, and a caller can lower the cap through
`:max_steps` (32 fits every proof from a tree of up to 2^32 entries). The cap limits a
path's length, not the `tree_size` a proof states. The path's length is counted no further
than one node past the required length, so a path of a million elements is refused after
reading one more than it needed, and no node is decoded or hashed until the length is
right. So the hashing a stranger can ask for is bounded by the cap. `walk/3` returns
`{:ok, root}` or an `{:error, reason}` naming the check that refused, and `verify/4`,
which also checks the root's format, returns `false` for all of them.

`proof_from_binary/1` returns `{:ok, proof}` or `{:error, reason}`, and accepts only the
canonical binary form: the index below the size and exactly the bytes the path needs. One
proof never has two encodings.

`proof_to_binary/1` raises `ArgumentError` on a proof that `walk/3` would refuse with its
default cap. It is for proofs you produced, not for input from a stranger.

The tree depth cap of 40 is a different kind of limit and should not be read as a load
control. It turns an impossible input into a clear error: it refuses a tree of more than
2^40 (about 1.1 trillion) entries, and memory is exhausted long before that. A finished
tree retains roughly 280 to 310 MB per million entries, and building one peaks at about
three times that, on top of the input list (measured at a million entries).

Construction has no limit of its own on the number of entries. `new/1` will attempt
whatever list it is handed, so tree construction belongs behind input you control.
Construction also raises rather than returning errors: `ArgumentError` for input that is
not a list of entry maps, an invalid key, an invalid hash, a duplicate key, or a depth
over the cap.

## Constant-time comparison

The final root comparison uses `:crypto.hash_equals/2`. This protects no secret. The
computed root, the expected root, the proof, and the leaf value are all public, so there
is no timing channel to close and nothing an attacker learns from the comparison that they
did not already hold. It is kept because it costs nothing and because it keeps the door
shut if a caller ever compares something that is not public. Presented as a habit, not as
a defense, and it should not appear in a security summary as though it were one.

## Platform requirements

Elixir 1.20, and so OTP 27 or newer. Beyond that the module depends only on `:crypto`,
`Base`, `Bitwise`, and the standard library.
