import pytest
from bingo import run_bingo

# A tiny shellcode that simply returns (x86-64 Linux: ret)
RET_SHELLCODE = bytes.fromhex("c3")

def test_ret_shellcode():
    # Should execute without raising
    run_shellcode(RET_SHELLCODE)
