import ctypes
import sys
from typing import Final

# --------------------------------------------------------------------------- #
# Platform-specific constants
# --------------------------------------------------------------------------- #
if sys.platform.startswith("win"):
    # Windows: VirtualAlloc + PAGE_EXECUTE_READWRITE
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    PAGE_EXECUTE_READWRITE: Final[int] = 0x40
    MEM_COMMIT: Final[int] = 0x1000
    MEM_RESERVE: Final[int] = 0x2000

    def _alloc(size: int) -> int:
        return _kernel32.VirtualAlloc(
            None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )

    def _free(addr: int) -> None:
        _kernel32.VirtualFree(addr, 0, 0x8000)  # MEM_RELEASE

elif sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
    # POSIX: mmap(PROT_READ|PROT_WRITE|PROT_EXEC)
    _libc = ctypes.CDLL("libc.so.6" if sys.platform != "darwin" else "libc.dylib")

    PROT_READ: Final[int] = 1
    PROT_WRITE: Final[int] = 2
    PROT_EXEC: Final[int] = 4
    MAP_PRIVATE: Final[int] = 2
    MAP_ANONYMOUS: Final[int] = 0x20 if sys.platform.startswith("linux") else 0x1000

    def _alloc(size: int) -> int:
        return _libc.mmap(
            None,
            size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )

    def _free(addr: int, size: int) -> None:
        _libc.munmap(addr, size)

else:
    raise RuntimeError(f"Unsupported platform: {sys.platform}")

# --------------------------------------------------------------------------- #
# Public function
# --------------------------------------------------------------------------- #
def run_bingo(shellcode: bytes) -> None:
    """
    Execute raw shellcode in the current process.

    Parameters
    ----------
    shellcode: bytes
        The raw machine code to execute.

    Raises
    ------
    ValueError
        If *shellcode* is empty.
    RuntimeError
        If memory allocation fails or the platform is unsupported.
    """
    if not shellcode:
        raise ValueError("shellcode must not be empty")

    size = len(shellcode)
    addr = _alloc(size)
    if addr in (0, -1):
        raise RuntimeError("Failed to allocate executable memory")

    try:
        # Copy shellcode into the buffer
        ctypes.memmove(addr, shellcode, size)

        # Cast to a callable with no arguments
        func = ctypes.CFUNCTYPE(None)(addr)
        func()
    finally:
        # Always release the memory
        _free(addr, size)
