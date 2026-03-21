import subprocess
import sys
import os
import tempfile
import atexit
from harnessreducer.utils import get_crash_tester_path
from pathlib import Path
import shutil

from harnessreducer.fdp_inline_from_trace import _load_trace, inline_source


__script_dir__ = os.path.dirname(os.path.realpath(__file__))
__project_root__ = Path(__script_dir__).parent.parent

treducer_dir = tempfile.mkdtemp(prefix="harness_reducer_")
def cleanup():
    try:
        shutil.rmtree(treducer_dir,ignore_errors=True)
    except OSError:
        pass
atexit.register(cleanup)


def get_project_root():
    return __project_root__

def get_fdp_header_dir():
    return os.path.join(get_project_root(), "include")

def get_crash_tester_path():
    return os.path.join(get_project_root(), "tests", "crash_tester.py")

def check_tree_reducer():
    output = subprocess.run(
        ["tree-reducer-c", "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if output.returncode != 0:
        raise Exception("tree-reducer is not available. Please ensure it is installed and in your PATH." + f"Error details: {output.stderr.strip() or output.stdout.strip()}")
    return

def tag_harness_with_fdp_ids(harness_path: str, start_id: int, marker: str) -> str:
    from fdp_tag_callsites import inject_ids

    with open(harness_path, "r", encoding="utf-8") as f:
        src = f.read()

    transformed, count = inject_ids(src, start_id, marker)
    tag_harnss_file = os.path.join(treducer_dir, os.path.basename(harness_path))
    with open(tag_harnss_file, "w", encoding="utf-8") as f:
        f.write(transformed)
    print(f"Injected {count} FDP callsite IDs into {harness_path}")

    return tag_harnss_file

def compile_dump_mode_harness(harness_path: str, extra_flags: str | None) -> str:
    tag_harness_bin = os.path.join(treducer_dir, "tagged_harness.out")
    compile_cmd = [
        "clang++",
        "-DFDP_MIN_MODE_DUMP",
        f"-I{get_fdp_header_dir()}",
        "-fsanitize=address,fuzzer,undefined",
        "-g",
        "-O0",
        harness_path,
        "-o",
        tag_harness_bin
    ]
    if extra_flags:
        compile_cmd.extend(extra_flags.split())        

    compile_proc = subprocess.run(
        compile_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if compile_proc.returncode != 0:
        err_msg = compile_proc.stderr.strip() or compile_proc.stdout.strip() or "Unknown compilation error"
        raise Exception("Failed to compile tagged harness with dump mode" + f"Error details: {err_msg}")
    return tag_harness_bin

def dump_fdp_trace(harness_bin: str, crash_input: str | None) -> str:
    fdp_trace_file = os.path.join(treducer_dir, "fdp_trace.log")
    env = os.environ.copy()
    env["FDP_TRACE_PATH"] = fdp_trace_file
    cmd = [harness_bin, crash_input] if crash_input else [harness_bin]
    run_proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if run_proc.returncode != 0:
        err_msg = run_proc.stderr.strip() or run_proc.stdout.strip() or "Unknown execution error"
        raise Exception("Failed to execute tagged harness in dump mode" + f"Error details: {err_msg}")
    if not os.path.exists(fdp_trace_file):
        raise Exception("FDP trace file was not created as expected.")
    return fdp_trace_file

def run_treereducer(harness_path: str, fdp_trace_file: str, crash_pattern: str, extra_args: str | None, crash_input: str | None) -> str:
    reduced_harness = os.path.join(treducer_dir, "reduced_harness.cpp")
    cmd = [
        "tree-reducer-c",
        "-j", "60",
        "-s", harness_path,
        "-o", reduced_harness,
        "--stable",
        "--min-reduction", "1",
        "--interesting-exit-code", "77"
        "--",
        get_crash_tester_path(),
        "@@.cpp",
        crash_pattern
    ]
    env = os.environ.copy()
    env["FDP_TRACE_PATH"] = fdp_trace_file
    env["EXTRA_FLAGS"] = extra_args if extra_args else ""
    env["CRASH_INPUT"] = crash_input if crash_input else ""

    run_proc = subprocess.run(
        cmd,
        env=env,
        stdout=subprocess.STDOUT,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if run_proc.returncode != 0:
        raise Exception("Failed to run tree-reducer")
    if not os.path.exists(reduced_harness):
        raise Exception("Reduced harness file was not created as expected.")
    return reduced_harness

def format_reduced_harness(reduced_harness_path: str):
    cmd = [
        "clang-format",
        "-i",
        "--style=LLVM",
        reduced_harness_path
    ]
    print(f"Formatting reduced harness with clang-format: {reduced_harness_path}")
    format_proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if format_proc.returncode != 0:
        err_msg = format_proc.stderr.strip() or format_proc.stdout.strip() or "Unknown formatting error"
        raise Exception("Failed to format reduced harness with clang-format" + f"Error details: {err_msg}")
    return

def inline_literals_in_reduced_harness(reduced_harness_path: str, fdp_trace_file: str):
    src = Path(reduced_harness_path).read_text(encoding="utf-8", errors="ignore")
    streams = _load_trace(Path(fdp_trace_file))
    transformed, count = inline_source(src, streams)
    Path(reduced_harness_path).write_text(transformed, encoding="utf-8")
    print(f"Inlined {count} FDP calls into {reduced_harness_path}")

def process(harness_path: str, extra_flags: str | None, crash_pattern: str, crash_input: str | None):
    check_tree_reducer()
    tag_harnss_file = tag_harness_with_fdp_ids(harness_path, start_id=100000, marker="FDP_ID")
    tag_harness_bin = compile_dump_mode_harness(tag_harnss_file, extra_flags)
    fdp_trace_file = dump_fdp_trace(tag_harness_bin, crash_input)
    reduced_harness = run_treereducer(tag_harnss_file, fdp_trace_file, crash_pattern, extra_flags, crash_input)
    format_reduced_harness(reduced_harness)


