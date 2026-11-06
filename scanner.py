"""Run Semgrep on user-provided source files, without executing their code."""
import json
import subprocess
from pathlib import Path

ALLOWED = {'.py', '.js', '.jsx', '.ts', '.tsx', '.sql', '.json', '.java', '.go', '.php', '.rb'}
EXCLUDED = {'node_modules', '.git', '.venv', 'dist', 'build', 'coverage'}
MAX_FILES = 300
MAX_FILE_BYTES = 500_000

def scan(root: Path):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError('Scan directory not found')
    command = ['semgrep', 'scan', "--config", "p/default", '--json', '--metrics=off', '--disable-version-check', '--timeout', '10', str(root)]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError('Semgrep is not installed. Run: pip install -r requirements.txt') from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('Scan exceeded 3 minutes') from exc
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError('Semgrep did not return JSON: ' + proc.stderr[-500:]) from exc
    if proc.returncode not in (0, 1):
        raise RuntimeError('Semgrep failed: ' + proc.stderr[-800:])
    results = []
    for item in data.get('results', []):
        path = Path(item.get('path', ''))
        try:
            relative = str(path.resolve().relative_to(root))
        except ValueError:
            relative = path.name
        extra = item.get('extra', {})
        results.append({
            'rule': item.get('check_id', 'unknown'),
            'file': relative,
            'line': item.get('start', {}).get('line', 0),
            'severity': extra.get('severity', 'INFO'),
            'message': extra.get('message', 'Potential security issue'),
            'code': extra.get('lines', '')[:1500],
        })
    return results, data.get('errors', [])
