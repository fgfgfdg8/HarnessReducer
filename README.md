# HarnessReducer

HarnessReducer is a reducer workflow for library fuzzing harnesses.
It focuses on preserving an existing crash while minimizing harness code,
with first-class support for `FuzzedDataProvider` (FDP).

## Install

1. Install `tree-reducer-c`:

```bash
cargo install treereduce-c
```

2. Use a Python 3.12+ environment and install project dependencies:

```bash
uv sync
source ./.venv/bin/activate
```

3. Ensure `clang++` and `clang-format` are available in `PATH`.

   On Ubuntu/Debian:
   ```bash
   sudo apt-get update && sudo apt-get install -y clang-format
   ```

## Complex FDP Example

The repository contains a complex FDP-based harness example:

- `examples/fdp_complex_crash_harness.cpp`

This example intentionally includes:

- Multiple parsing stages (`header`, `records`, `metrics`)
- Rich FDP consumption APIs (`ConsumeBytesAsString`, `ConsumeIntegral`,
	`ConsumeRandomLengthString`, `ConsumeBytes`, `ConsumeFloatingPoint`, `ConsumeBool`)
- A deterministic crash gate to demonstrate crash-preserving reduction

### Build The Example

```bash
clang++ -std=c++17 -Iinclude -O0 -g -fsanitize=fuzzer,address \
	examples/fdp_complex_crash_harness.cpp \
	-o /tmp/fdp_complex_demo.out
```

## Testing

Run automated tests (compiles and executes the example):

```bash
uv run python -m unittest tests/test_fdp_complex_example.py -v
```

## CLI Usage

After installation, run:

```bash
harnessreducer <harness.cpp> [--extra-flags "..."] [--crash-input seed.bin] [--crash-pattern "regex"] [--llm] [-o poc.cpp] 
```

### Argument Descriptions

- **`harness`** (positional): Path to the original C++ harness source file to be reduced.
- **`--extra-flags`**: Additional compiler flags (e.g., `-I`, `-L`, `-l`, `-std=c++17`). These are appended to the base compilation command used for crash verification:
  ```bash
  clang++ -fsanitize=address,fuzzer,undefined -g -O0 <harness> -o <output> [EXTRA_FLAGS]
  ```
  _Note: During reduction, the tool automatically adds `-I<project_root>/include` and `-DFDP_MIN_MODE_REPLAY` if FDP tracing is enabled._
- **`--crash-input`**: Path to the binary input file (seed) that triggers the crash.
- **`--crash-pattern`**: A regex used to identify the target crash. If not provided, it is automatically extracted from the first execution (e.g., specific ASan/UBSan signatures or assertion messages).
- **`--work-dir`**: Specified directory for intermediate files (tagged source, tracing logs, build artifacts). If not set, a temporary directory is used.
- **`--llm`**: Optional. Enables a final semantic minimization pass using a Large Language Model. Need LLM to be configured. See [LLM Configuration](#llm-configuration) section for more details.
- **`-o`, `--output`**: (Required) The final path for the minimized `poc.cpp`.

### Examples

Use a fixed working directory:

```bash
harnessreducer <harness.cpp> --work-dir ./workdir -o poc.cpp
```

Equivalent module invocation:

```bash
uv run python -m harnessreducer <harness.cpp> [--extra-flags "..."] [--crash-input seed.bin] [--crash-pattern "regex"] [-o poc.cpp]
```

### Real-world Libvpx Examples

Below are examples of reducing libvpx harnesses using absolute paths. The reducer automatically detects the crash pattern and necessary sanitizers from the execution output.

**1. Crash 007 (NULL Pointer Dereference)**
```bash
harnessreducer /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_007/harness_009.cpp \
  --crash-input /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_007/crash-bd979b0ede456b5a16f139d812976e51e31b61ca \
  --extra-flags "-I/mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/build/sanitizer/include /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/build/sanitizer/lib/libvpx.a" \
  --work-dir /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_007/workdir \
  -o /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_007/poc.cpp
```

**2. Crash 019 (Signed Integer Overflow)**
```bash
harnessreducer /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_019/harness_018.cpp \
  --crash-input /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_019/crash-1093e80c7a0d2b29bb969bfb65d1cab8ada88ff9 \
  --extra-flags "-I/mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/build/sanitizer/include /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/build/sanitizer/lib/libvpx.a" \
  --work-dir /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_019/workdir \
  -o /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_019/poc.cpp
```

**3. Crash 030 (Segmentation Fault)**
```bash
harnessreducer /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_030/harness_030.cpp \
  --crash-input /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_030/crash-dc3429ef98d971c0cd5bb7c069a2002152f489c8 \
  --extra-flags "-I/mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/build/sanitizer/include /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/build/sanitizer/lib/libvpx.a" \
  --work-dir /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_030/workdir \
  -o /mnt/raid/FuzzAgentExp/libvpx/libvpx_exp_24h_1/crash_reports/crash_030/poc.cpp
```

### LLM Configuration

HarnessReducer supports an optional semantic reduction pass using a Large Language Model (LLM) after structural reduction is completed and FDP calls are inlined. This pass aims to further simplify logic, perform constant folding, and remove redundancies that structural tools might miss.

To use this feature, add the `--llm` flag to your command. The required dependencies (`openai` and `python-dotenv`) are automatically compiled and installed via `uv sync` from the `pyproject.toml` definition. You just need to ensure the following environment variables are set (either explicitly in your shell or by creating a `.env` file at the project root):

- **`OPENAI_API_KEY`**: Your API key.
- **`OPENAI_BASE_URL`**: The API base URL (e.g., `https://api.openai.com/v1`).
- **`OPENAI_MODEL`**: The specific model name (e.g., `gpt-4o` or compatible).

Example `.env` file:
```env
OPENAI_API_KEY=your_key
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o
```


## Python API Usage

```python
from harnessreducer import ReductionConfig, reduce_with_config

config = ReductionConfig(
	harness_path="examples/fdp_complex_crash_harness.cpp",
	crash_pattern="AddressSanitizer|runtime error",
	extra_flags="-std=c++17",
	crash_input="seed.bin",
)

result = reduce_with_config(config)
print(result.reduced_harness)
```

## Notes

- FDP header is expected at `include/fuzzer/FuzzedDataProvider.h`.
- The reducer pipeline Python code is in `src/harnessreducer/`.
- Internal layering:
	- `harnessreducer.api`: orchestration/public API
	- `harnessreducer.fdp_transform`: FDP AST tagging + trace inlining
	- `harnessreducer.reducer_runner`: compile/run/tree-reducer execution
- Legacy compatibility entrypoint is still available at `python -m harnessreducer.main`.
- Legacy compatibility entrypoint is still available at `uv run python -m harnessreducer.main`.