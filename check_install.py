# check_install.py
import subprocess
from pathlib import Path
import sys

# 가상 환경 경로 설정
VENV_DIR = Path(__file__).resolve().parent / "venv"
if sys.platform == "win32":
    venv_python_exe = VENV_DIR / "Scripts" / "python.exe"
else:
    venv_python_exe = VENV_DIR / "bin" / "python"

print("="*50)
# 가상 환경 생성 (없으면)
if not VENV_DIR.is_dir():
    print(f"--- Creating venv in {VENV_DIR} ---")
    subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)

print(f"--- Testing direct installation using: {venv_python_exe} ---")

# 가상 환경의 pip를 이용해 mitmproxy를 직접 설치하는 명령어
# 모든 출력을 화면에 그대로 보여주기 위해 capture_output을 사용하지 않음
cmd = [str(venv_python_exe), "-m", "pip", "install", "mitmproxy"]

print(f"--- Running command: {' '.join(cmd)} ---")
print("="*50)

# subprocess 실행
result = subprocess.run(cmd)

print("="*50)
print(f"--- Test finished with return code: {result.returncode} ---")
print("="*50)