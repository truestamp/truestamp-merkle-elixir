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

An inclusion proof is a claim about one 32-byte value and one root:

> This leaf hash was one of the leaves of the tree whose root is that root hash.

That is the whole claim. It establishes existence (the value was present when the tree
was built) and integrity (change one bit of the value, or one bit of any sibling on the
path, and the recomputed root no longer matches). `verify/4` recomputes the root from the
leaf value and the proof's siblings and compares it against the root you supplied, so the
proof is only as meaningful as your confidence in that root. `walk/3` recomputes the same
root and hands it back without being given one.

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
instance, a metadata hash bound into the leaf value fixes a submission window and the
block holding that leaf is committed to public blockchains, and the two together are what
pin a submission window around the leaf. Even then the claim is about submission, not
about when the underlying data came into existence.

**Not authorship.** Nothing about who submitted a value is hashed into a leaf. If you need
to attribute a value to a submitter, that binding has to be arranged upstream or carried
outside the proof entirely. Truestamp records authorship as `Item.creator_id`,
deliberately outside every hash.

**Not an append-only history.** Only inclusion proofs exist here. There are no consistency
proofs, no Signed Tree Heads, and no log monitoring, so none of the append-only guarantees
a Certificate Transparency log provides are available from this module. Tamper evidence
over time has to be built around the roots by the caller. Truestamp gets it from the block
hash chain and the public blockchain commitments.

**Not any binding between a key and a hash.** This is the one most likely to be assumed.
`verify/4` takes a leaf hash, a proof and a root, and `walk/3` a leaf hash and a proof.
There is no key argument, and there is no place to put one. `proof/2` takes a key, but
only to look up which leaf position to walk from; the key is never hashed into a leaf, an
interior node, or the root. Keys affect leaf *order* (the default `sort: true` orders
leaves by key, and a different order gives a different root) and they are checked for
uniqueness at construction, but no proof ever carries evidence about which key a leaf was
filed under.

So a valid proof for hash `H` under root `R` says exactly that `H` was in that tree. It
does not say `H` belonged to record 42, or to account X, or to a document with a given
name. If your application needs that binding, commit the identifier into the leaf hash
upstream, before the value reaches the tree. Truestamp is an example of how that looks in
practice: `item_hash` is a domain-separated composite over the record's id along with its
claims and metadata hashes, so the id is inside the value the proof is about. A system
that hands this library a bare content digest and stores the identifier alongside it in a
database has no cryptographic link between the two, and this library will not supply one.

## Hash construction and domain separation

Leaves and interior nodes are hashed in separate domains:

    leaf     = SHA-256(0x00 || leaf_hash)          leaf_hash is 32 bytes
    interior = SHA-256(0x01 || left || right)      left and right are 32 bytes each
    empty    = SHA-256("")                         root of a tree with no leaves

The prefix byte is the primary defense, and what it defends against is the classic
second-preimage attack on unprefixed Merkle trees. Without it, the 64-byte concatenation
`left || right` sitting under an interior node hashes to the same value as a 64-byte
"leaf" holding those same bytes, so anyone could present an interior node's children as a
leaf and produce a shorter valid-looking path to the root. With the prefix, a value that
was hashed as an interior node can never be reinterpreted as a leaf: verification hashes
the supplied value with `0x00`, an interior node was hashed with `0x01`, and the two
results differ. This was checked by sweeping every node value at every level of a padded
tree against both its own path and the level-0 path at the same index. No forgery
succeeded.

The 32-byte input check is secondary, defense in depth, and it should not be described as
what prevents interior-node forgery. It refuses a 64-byte value at the door rather than
letting it through to be rejected by the prefix rule, and it keeps the hash surface
uniform, but the domain separation is what makes the attack impossible rather than merely
inconvenient.

None of this hashing is homegrown: the leaf and node construction follows RFC 6962. The
padded tree shape does not, so a verifier written strictly to that standard computes a
different root at any leaf count other than 0, 1, or a power of two. The proof encoding is
likewise specific to this library.

## Canonical hex

Every hash crossing the API is exactly 64 lowercase hex characters, on the way in and on
the way out: the digests you supply for entries, the root hashes you get back, leaf values,
and proof siblings alike. Non-canonical input is refused, never normalized. `new/2` and the
raises `ArgumentError`; `walk/3` returns an error and `verify/4` returns `false`.

Refusing rather than downcasing is deliberate. Two spellings of the same hash would be
two distinct leaves in the leaf index and two distinct byte strings on the wire, and a
library that quietly accepts both invites a caller to believe the spelling does not
matter. The cost is that an uppercase hash produces a `false` from `verify/4` that looks
exactly like a proof that does not check out; `walk/3` names the refusal instead. Hexdump
tools commonly emit uppercase, so downcase before calling rather than reading that `false`
as a cryptographic result.

The validators walk the bytes rather than matching a regular expression. That is faster,
and it closed a real hole: PCRE's `$` matches before a trailing newline, so a 64-hex hash
with a `\n` appended passed validation and then raised out of `Base.decode16!/2` deep
inside verification, in a function documented never to raise. Matching a fixed 64-byte
head cannot do that.

## The reserved padding constant

The tree is built by padding the leaf set up to the next power of two and hashing a
perfect binary tree. That shape is frozen: roots built this way are already in circulation
and committed to public blockchains, so it cannot be revised. Every padding slot stands for
one reserved value:

    PADHASH      96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7
                 = SHA-256(0x00 0x00), the leaf *value* a padding slot carries

    padding leaf d37300dc2c6e038a83ee197ca0e181a77f6875afd9f537d31ca4995876481319
                 = SHA-256(0x00 || PADHASH), the *leaf hash* stored in the tree

Padding slots are placed by the tree, never by a caller. They carry no key, so they are
absent from the leaf index and `proof/2` will not emit a proof for one. The `__pad__` key
prefix, in any case, stays reserved: construction refuses a caller's key that begins with
it.

`PADHASH` is refused on both ends. `new/2` raises `ArgumentError` on it, `walk/3` returns
`{:error, :reserved_leaf}` and `verify/4` returns `false` when it is presented as the value
being proved.

Both halves are needed. The attack is cheap and requires no cryptography: whoever owns the
last real leaf of a padded tree can assemble a complete, valid path for a padding slot out
of their own published proof and their own leaf hash, and before the reject that forged
proof verified. Refusing it only at construction closes nothing, because the attacker never
calls the constructor. Refusing it only at verification would silently break a caller who
genuinely hashed the two-byte file `0x0000` and used the digest as a leaf: their tree would
build, their proof would generate, and verification would return `false` forever with no
explanation. The input reject turns that into a loud build-time error naming the constant,
and it is what earns the right to say that a proof for `PADHASH` is always a proof of a
padding slot rather than of a real entry.

The reject applies to the leaf value only. The padding *leaf hash* `d37300dc...` is an
ordinary sibling in most proofs from a padded tree and must keep verifying, so the step
parser deliberately does not look for it. Rejecting siblings would break verification
for a large fraction of all real entries.

There is no wider family of forgeable constants. Interior node values, including the
all-padding subtree hashes and the empty-tree root, are safe by domain separation:
presenting one as a leaf re-hashes it with `0x00`. `PADHASH` was forgeable for exactly one
reason, that it is the leaf *input* of a real leaf rather than a node value, so a single
constant and a single comparison close it completely.

Whether the input reject can ever inconvenience you depends on where your leaf values come
from. A caller hashing arbitrary bytes might one day be handed that two-byte file, and
will get the build-time error. A caller whose leaf values are server-derived
domain-separated composites cannot reach it at all. Truestamp is in the second position:
its leaf values (`item_hash`, `observation_hash`, `block_hash`) each carry a reserved
application prefix byte and have preimages over a hundred bytes long, while `PADHASH`'s
preimage is two bytes beginning with `0x00`. A collision would be a SHA-256 break, and a
submitter cannot grind toward one because they do not choose the leaf value.

## What an observer can infer from a proof

A proof discloses more than the leaf it proves. The padding constants are public and
recomputable by anyone: `SHA-256(0x00 || PADHASH)` gives the padding leaf hash, and
iterating `SHA-256(0x01 || x || x)` gives the hash of an all-padding subtree at any level.
From one proof, with no other access, an observer learns:

- the tree depth, which is the proof length, and therefore the padded size `2^depth`
- the proved leaf's exact index, decoded from the `l` and `r` direction tags
- which sibling subtrees are pure padding, by equality against those constants, and
  therefore a range for the real leaf count. For a leaf near the end of the tree the range
  collapses and the exact count is recovered.

This is accepted rather than overlooked. Deterministic padding is a requirement, not a
slip: a third party has to be able to recompute the root from published data alone, and
random padding values would have to be published to allow that, which republishes the
count. A keyed PRF has the same defect, since the key would have to be published to
verifiers. Whether the leakage matters is a question about your data, not about the tree.
Truestamp publishes the leaf count per block on an unauthenticated explorer anyway, so
there the inference discloses what the front end states outright.

Worth noting that padding to a power of two *reduces* leakage relative to an unpadded
tree, where proof length varies per leaf and the shape encodes the leaf count directly.
The uniform shape helps; the recognizable constant is the part that hurts.
Refusing `PADHASH` as an input hash also removes the only cheap way to spoof this
inference, since a caller can no longer make a real leaf hash to the padding constant.

## Bounds, limits, and which entry points face untrusted input

`walk/3`, `verify/4`, `steps_from_binary/1`, and `decode_proof_base64/1` are the entry
points safe to put in front of untrusted callers. All four cap the proof at 64 steps
before hashing anything, which is the real bound on the hashing a stranger's bytes can ask
for, and `walk/3` and `verify/4` accept a lower cap through `:max_steps` (Truestamp passes
32). `walk/3` and `verify/4` never raise on their input: each validates the leaf format,
the reserved constant, the step count (counting no further than one past the cap), and
every step before hashing anything. `walk/3` returns `{:ok, root}` or an
`{:error, reason}` naming the check that refused, and `verify/4`, which also checks the
root's format, returns `false` for all of them. Only an invalid option raises. The
decoders return `{:ok, steps}` or `{:error, reason}`, and accept only the canonical binary
form, so one path never has two encodings. A 64-step proof spans a tree of 2^64 leaves,
past anything that could be built, so the cap costs no legitimate proof.

`steps_to_binary/1` and `encode_proof_base64/1` raise `ArgumentError` on input that would
not survive the round trip. They are for proofs you produced, not for bytes from a
stranger.

The tree depth cap of 40 is a different kind of limit and should not be read as a load
control. It keeps the depth arithmetic in range. A tree deep enough to reach it holds
about a trillion leaves, and memory is exhausted long before that, at roughly 300 MB
retained per million leaves plus comparable transient use during construction.

Construction has no limit of its own on the number of entries. `new/2` will attempt
whatever list it is handed, so tree construction belongs behind input you control. Construction also raises rather than
returning errors: `ArgumentError` for an invalid key, an invalid hash, the reserved padding
constant, a duplicate key, or a depth over the cap.

## Constant-time comparison

The final root comparison uses `:crypto.hash_equals/2`. This protects no secret. The
computed root, the expected root, the proof, and the leaf value are all public, so there
is no timing channel to close and nothing an attacker learns from the comparison that they
did not already hold. It is kept because it costs nothing and because it keeps the door
shut if a caller ever compares something that is not public. Presented as a habit, not as
a defense, and it should not appear in a security summary as though it were one.

## Platform requirements

OTP 25 or newer, which is where `:crypto.hash_equals/2` arrived. Beyond that the module
depends only on `:crypto`, `Base`, `Bitwise`, and the standard library.
