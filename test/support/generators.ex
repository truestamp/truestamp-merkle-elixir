# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Generators do
  @moduledoc false

  # StreamData generators the property tests share.

  import ExUnitProperties
  import StreamData

  # A digest: 64 lowercase hex characters.
  def digest, do: string([?a..?f, ?0..?9], length: 64)

  # A valid key: lowercase letters and digits with optional . - _ separators, up to 36
  # characters. It never starts or ends with a separator, so nothing is lost to
  # trimming, and never starts with the reserved padding prefix.
  def key do
    gen all(
          first <- one_of([member_of(?a..?z), member_of(?0..?9)]),
          middle <- string([?a..?z, ?0..?9, ?., ?-, ?_], max_length: 34),
          last <- one_of([member_of(?a..?z), member_of(?0..?9)])
        ) do
      to_string([first] ++ String.to_charlist(middle) ++ [last])
    end
  end

  def entry do
    gen all(key <- key(), digest <- digest()) do
      %{"key" => key, "hash" => digest}
    end
  end
end
