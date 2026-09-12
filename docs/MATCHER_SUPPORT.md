# Matcher support

The upgrade replaces fixed VLE word masking with decoded operand masks. Matching produces review candidates, not semantic-equivalence proof or permission to transfer annotations.

## Supported instruction fixtures

`MatcherInstructionProgramDbTest` loads real Ghidra 12.0.3 languages, disassembles positive and negative examples, and requires the expected instructions to exist. Classifier-only tests are separate.

| Language | Qualified fixture | Context |
|---|---|---|
| `x86:LE:32:default` | Relative CALL relocation; CALL/JMP distinction; compound-memory base register retained | 32-bit x86 |
| `ARM:LE:32:v7` | BL relocation; BL/B distinction | Explicit ARM TMode |
| `ARM:LE:32:v8T` | Mixed-width Thumb BL relocation; BL/B.W distinction | Explicit Thumb TMode |
| `PowerPC:BE:64:VLE-32addr` | Mixed-width e_bl relocation; e_bl/e_b distinction | Proven VLE context across the range |

This is qualification of those instruction fixtures and conservative mask construction, not exhaustive coverage of every opcode. VLEALT, x86-64, big-endian ARM and other language IDs are not enabled for masked function matching. Ghidra 12.0.3 does not supply the synthetic `PowerPC:BE:32:VLE` ID used by legacy classifier tests.

## Function matcher contract

- `mask_mode=none` compares exact raw bytes on any architecture. The entry window must fit readable bytes within the source function body. The default 24-byte window shrinks for short functions; explicitly oversized requests fail.
- `auto` and `aggressive` use the same decoded relocatable-operand rule. The builder retains opcode bits and compound operands containing registers. It rejects low-information, undecoded, unknown-context and unsupported-language windows. A partial final instruction is clipped to a complete instruction boundary and the returned pattern/mask reflects that window.
- Masked source/target language, endian and compiler identities must agree. ARM/Thumb and VLE context must agree; candidate instructions must produce the same mask. Unsupported requests fail with guidance to use explicit raw matching, native Version Tracking, or available BSim.
- Functions larger than the requested window are candidate-ranked by size; a matching prefix is not proof of full correspondence. `confidence` is legacy ranking evidence, not a probability.

The builder API is static `plan(Program, Function, byte[], MaskMode, TaskMonitor)` or `plan(Program, Address, int, MaskMode, TaskMonitor)`. Plans report `RAW`, `RELOCATABLE_OPERANDS`, or `UNSUPPORTED`, the actual window, mask and explanation.

## Scan and output bounds

Both `function_byte_matcher` and `search_bytes` scan loaded, initialized executable memory by default. Patterns are limited to 65,536 bytes and the cumulative selected executable scan to 1 MiB. Larger selections fail before scanning; narrow `start_address` and `end_address`. Result counts are capped at 1,000 and complete JSON envelopes at 120,000 bytes before backend context decoration. Reduce the result limit/window if a response is too large.

Results include complete/truncated/cancelled scan evidence. A capped or incomplete search never reports uniqueness. `search_bytes` returns entry/interior/block locations and containing function identity; it remains a byte search, not a cross-program join.

## Region transfer

`bulk_region_transfer` uses the shared instruction builder for qualified VLE offset discovery and verification, requiring matching source/target masks. Compatible non-VLE architectures use exact bytes. Every compared byte must agree; unreadable or partial windows fail. The legacy four-byte word heuristic has been removed. Region transfer does not expose generic architecture-masked matching or PORT metadata; the porting workflow uses reviewed `bulk_transfer_labels` rows for checkpoints.

See [release validation](UPGRADE_FINAL_VALIDATION_2026-09-12.md) for executed test counts, artifact identity and remaining runtime gates.
