# Read latency evidence

The final probe on 2026-09-12 used the actual extension JAR and dependency JARs extracted from the release ZIP in a fresh disposable Ghidra 12.0.3 process. Its loaded source fingerprint was `4d4a53463f40fab847c6331be2bf182594fcaeebff73d26c4e7c8d53689b9be0`.

`validation/benchmark_reads.py` requested structured native decompiler output for the exact source program, function `1000`, with `max_items=20`. All nine calls returned completed C output: one first-observed call, seven warm calls, and one `max_chars=1024` call. First-observed latency was 362.17 ms; warm median was 3.40 ms. The complete HTTP responses totaled 36,253 bytes. This fresh process had no earlier decompile before the root-controlled benchmark, but the script deliberately labels the sample first-observed rather than inferring coldness.

This supports the configurable 500 ms inline read window for the tiny fixture. It does not establish production throughput, large-function behavior, contention performance, or native allocation bounds. Generic task submission/result-bearing wait is covered separately by latch and task lifecycle tests. The probe follows a task if returned and requires the nested operation's completed C result; a successful submission alone cannot pass.

Raw evidence is retained locally in `build/upgrade-validation/final-benchmark-v2.json`; rerun instructions are in [the validation harness guide](VALIDATION_HARNESS.md).
