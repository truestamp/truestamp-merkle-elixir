# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# Truestamp.Merkle from end to end: build a tree, prove an entry, verify the proof, and
# store it. Run it with `mix run examples/usage.exs` (or `task example`). Each step
# checks its own result, so the script stops if anything differs from what it shows.

alias Truestamp.Merkle

# 1. Entries. Each is a key, naming a record, and the SHA-256 digest of that record's
#    content as 64 lowercase hex characters. The tree hashes digests, never documents.
documents = %{
  "invoice-2026-001" => "Invoice 2026-001: 3 widgets, 42.00 USD",
  "invoice-2026-002" => "Invoice 2026-002: 1 gadget, 17.50 USD",
  "receipt-2026-001" => "Receipt 2026-001: paid in full"
}

digest = fn content -> :crypto.hash(:sha256, content) |> Base.encode16(case: :lower) end
entries = for {key, content} <- documents, do: %{"key" => key, "hash" => digest.(content)}

# 2. Build the tree and read its root. Entries are sorted by key, so the order they
#    arrive in does not change the root.
tree = Merkle.new(entries)
root = Merkle.root(tree)
^root = Merkle.root(Merkle.new(Enum.reverse(entries)))
IO.puts("root:  #{root}")

# 3. Prove one entry. The proof is its position, the tree's size and the path of
#    sibling hashes from its leaf up to the root.
proof = Merkle.proof(tree, "invoice-2026-002")
%{leaf_index: 1, tree_size: 3, path: [_, _]} = proof
IO.puts("proof: #{inspect(proof)}")

# 4. Verify it. Anyone holding the document, the proof and a root they trust can do this.
#    Take the tree size from the same place as the root (here, the count published with
#    it): the root does not fix the size, so a size read only from the proof proves
#    that the digest is in the tree, but not where.
published = %{root: root, tree_size: 3}
invoice = documents["invoice-2026-002"]

true = proof.tree_size == published.tree_size
true = Merkle.verify(digest.(invoice), proof, published.root)
IO.puts("verify(invoice-2026-002): true")

# 5. A changed document fails, and walk/3 names why a malformed proof was refused.
false = Merkle.verify(digest.("Invoice 2026-002: 1 gadget, 99.50 USD"), proof, root)
IO.puts("verify(a changed invoice): false")

short = %{proof | path: tl(proof.path)}
{:error, :wrong_path_length} = Merkle.walk(digest.(invoice), short)
IO.puts("walk(a proof missing a node): {:error, :wrong_path_length}")

# 6. Store the proof. The binary form suits a database column; the proof map itself
#    suits JSON.
binary = Merkle.proof_to_binary(proof)
{:ok, ^proof} = Merkle.proof_from_binary(binary)
IO.puts("binary form: #{byte_size(binary)} bytes")

decoded = proof |> JSON.encode!() |> JSON.decode!()

from_json = %{
  leaf_index: decoded["leaf_index"],
  tree_size: decoded["tree_size"],
  path: decoded["path"]
}

true = Merkle.verify(digest.(invoice), from_json, root)
IO.puts("verify(the proof read back from JSON): true")
