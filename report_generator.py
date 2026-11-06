"""Create a portable Markdown assessment report."""
from collections import Counter
from datetime import datetime, timezone

def generate(findings, analyzed, errors):
    counts = Counter(str(f.get('severity', 'INFO')).upper() for f in findings)
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    lines = ['# CDF AI Security Assessment', '', f'Generated: {now}', '',
             '## Executive summary', '',
             f'Semgrep detected **{len(findings)} potential findings**. '
             f'ERROR: {counts["ERROR"]}; WARNING: {counts["WARNING"]}; INFO: {counts["INFO"]}.', '',
             f'AI explanations provided for **{len(analyzed)}** findings. '
             'Scanner results are potential issues, not confirmed exploits. Human review is required.', '',
             '## Findings', '']
    if not findings:
        lines += ['No findings detected by the selected Semgrep rules. This does not establish that the code is secure.', '']
    lookup = {(f['file'], f['line'], f['rule']): f for f in analyzed}
    for i, finding in enumerate(findings, 1):
        ai = lookup.get((finding['file'], finding['line'], finding['rule']), {})
        lines += [f'### {i}. {finding["rule"]}', '',
                  f'- **Severity:** {finding["severity"]}',
                  f'- **Location:** `{finding["file"]}:{finding["line"]}`',
                  f'- **Scanner finding:** {finding["message"]}',
                  f'- **AI risk explanation:** {ai.get("risk", "Not analyzed by AI")}',
                  f'- **Recommended fix:** {ai.get("fix", "Manual review needed")}', '']
        if ai.get('secure_example'):
            lines += ['**Illustrative secure example (not tested):**', '', '```', ai['secure_example'], '```', '']
    if errors:
        lines += ['## Scan warnings', '', f'{len(errors)} Semgrep warnings/errors were reported. Review the scanner output.', '']
    lines += ['## Overall assessment', '',
              'Review high-risk findings first, verify each issue in context, apply safe fixes, and rescan. '
              'No changes were applied automatically.', '']
    return '\n'.join(lines)
