import os
from pathlib import Path

__script_dir__ = os.path.dirname(os.path.realpath(__file__))
__project_root__ = Path(__script_dir__).parent.parent


def get_project_root():
    return __project_root__

def get_fdp_header_dir():
    return os.path.join(get_project_root(), "include")

def get_crash_tester_path():
    return os.path.join(get_project_root(), "tests", "crash_tester.py")