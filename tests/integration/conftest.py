"""Integration test fixtures: build the NASM probe binary, open it in a
real (headless) IDA session via `idapro`/idalib, and hand tests the
resulting function addresses. Everything here is skipped automatically —
not errored — when IDA/idalib isn't available, so `pytest tests/unit` stays
green on any machine and only `pytest tests/integration` needs a real IDA
Pro installation.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
ASM_SOURCE = FIXTURES_DIR / "probe.asm"
BINARY_PATH = FIXTURES_DIR / "probe"


def _idapro_available() -> bool:
    try:
        import idapro  # noqa: F401
    except Exception:
        return False
    return True


def _toolchain_available() -> bool:
    return shutil.which("nasm") is not None and shutil.which("ld") is not None


requires_ida = pytest.mark.skipif(not _idapro_available(), reason="idapro/idalib not importable in this environment")


def _build_probe_binary() -> Path:
    if BINARY_PATH.exists() and BINARY_PATH.stat().st_mtime > ASM_SOURCE.stat().st_mtime:
        return BINARY_PATH
    if not _toolchain_available():
        pytest.skip("nasm/ld not available to build the integration fixture binary")
    obj_path = FIXTURES_DIR / "probe.o"
    subprocess.run(["nasm", "-f", "elf32", str(ASM_SOURCE), "-o", str(obj_path)], check=True)
    subprocess.run(["ld", "-m", "elf_i386", "-o", str(BINARY_PATH), str(obj_path)], check=True)
    # A database left over from a previous build would be reopened as-is,
    # silently testing the *old* binary — every function would still be
    # found by name and every assertion would run against stale analysis.
    for stale in FIXTURES_DIR.glob("probe.i*"):
        stale.unlink()
    for suffix in (".id0", ".id1", ".id2", ".nam", ".til"):
        leftover = FIXTURES_DIR / f"probe{suffix}"
        if leftover.exists():
            leftover.unlink()
    return BINARY_PATH


@pytest.fixture(scope="session")
def ida_session():
    """Opens `probe` in a real headless IDA database for the whole test
    session; closes it on teardown. Skips (doesn't error) if idapro/idalib
    or the assembler toolchain aren't available."""
    if not _idapro_available():
        pytest.skip("idapro/idalib not importable in this environment")
    binary = _build_probe_binary()

    import idapro

    idapro.open_database(str(binary), True)
    import ida_auto

    ida_auto.auto_wait()
    try:
        yield binary
    finally:
        idapro.close_database()


@pytest.fixture(scope="session")
def probe_functions(ida_session):
    import ida_funcs
    import ida_name

    names = [
        "target_func",
        "caller_push_seq",
        "caller_reg_indirect",
        "caller_return_chain",
        "decrypt_then_call",
        "caller_tail_call",
        "caller_sib_shadow",
        "caller_in_loop",
        "caller_neg_disp",
        "caller_partial_reg",
    ]
    result = {}
    for name in names:
        ea = ida_name.get_name_ea(0, name)
        assert ea != 0xFFFFFFFF and ea is not None, f"function {name!r} not found by IDA auto-analysis"
        assert ida_funcs.get_func(ea) is not None, f"{name!r} not recognized as a function by IDA"
        result[name] = ea
    return result
