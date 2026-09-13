"""Windows CLI Ctrl+C smoke test. Generates and retains only .test-data fixtures.

Run from the repository root after Release build: python scripts/verify-console-cancel.py
The signal sender is a separate hidden process, so the test never attaches the parent console.
"""
import ctypes
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import uuid

if len(sys.argv) == 3 and sys.argv[1] == "--signal":
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.FreeConsole()
    if not api.AttachConsole(int(sys.argv[2])):
        raise OSError(ctypes.get_last_error(), "AttachConsole")
    api.SetConsoleCtrlHandler(None, True)
    if not api.GenerateConsoleCtrlEvent(0, 0):
        raise OSError(ctypes.get_last_error(), "GenerateConsoleCtrlEvent")
    time.sleep(0.3)
    api.FreeConsole()
    sys.exit(0)

if sys.platform != "win32":
    raise SystemExit("Windows console smoke test requires Windows.")
repo = Path(__file__).resolve().parent.parent
cli = repo / "src/FileGuard.Cli/bin/Release/net10.0/fileguard.dll"
if not cli.is_file():
    raise SystemExit("Build the Release solution first.")
fixture = repo / ".test-data" / ("console-" + uuid.uuid4().hex)
files = fixture / "files"
files.mkdir(parents=True)
with (files / "slow.bin").open("wb") as output:
    output.truncate(8 * 1024 * 1024)
state = fixture / "state"
startup = subprocess.STARTUPINFO()
startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
startup.wShowWindow = 0
with (fixture / "stdout.json").open("wb") as output, (fixture / "stderr.txt").open("wb") as errors:
    child = subprocess.Popen(
        ["dotnet", str(cli), "scan", str(files), "--data", str(state),
         "--hash-all", "--bytes-per-second", "32768", "--json"],
        cwd=repo, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
        creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            database = state / "fileguard.db"
            if database.is_file():
                try:
                    with sqlite3.connect(database, timeout=0.1) as connection:
                        rows = connection.execute("SELECT json FROM records WHERE kind='scan'").fetchall()
                    if rows and json.loads(rows[0][0])["state"] == "Hashing":
                        break
                except sqlite3.OperationalError:
                    pass
            if child.poll() is not None:
                raise AssertionError("CLI exited before reaching Hashing")
            time.sleep(0.05)
        else:
            raise AssertionError("CLI did not reach Hashing before timeout")
        subprocess.run([sys.executable, str(Path(__file__).resolve()), "--signal", str(child.pid)],
                       check=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        assert child.wait(timeout=15) == 130, "Ctrl+C must return 130"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
document = json.loads((fixture / "stdout.json").read_text(encoding="utf-8"))
assert document["schemaVersion"] == 1
with sqlite3.connect(state / "fileguard.db") as connection:
    scan = json.loads(connection.execute("SELECT json FROM records WHERE kind='scan'").fetchone()[0])
assert scan["state"] == "Cancelled" and scan["finishedUtc"]
with (files / "slow.bin").open("r+b") as source:
    source.write(b"handles released")
print(json.dumps({"schemaVersion": 1, "consoleSignal": "CTRL_C_EVENT", "exitCode": 130,
                  "persistedState": scan["state"], "jsonStdout": True, "result": "passed"}))
