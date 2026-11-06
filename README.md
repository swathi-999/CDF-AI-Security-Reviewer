# CDF AI Security Reviewer

**Find → Fix → Fortify**: an AI-assisted source-code security review prototype for the CDF CyberSec Hackathon.

## Features
- Upload a ZIP of a source repository and scan supported source files without executing them.
- Detect potential security vulnerabilities with Semgrep.
- Optional OpenAI-powered explanations and illustrative secure-code recommendations.
- Show severity, filename, line number, and rule ID.
- Download a Markdown security assessment report.

## Requirements
- Python 3.10+ and internet access (Semgrep rule download and OpenAI API).
- OpenAI API key and available API credits for AI analysis; ChatGPT subscription is separate.

## Quick start (macOS)
```bash
cd CDF-AI-Security-Reviewer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```
Edit `.env` and replace `your_api_key_here` with a valid API key. Do not publish this file.

```bash
streamlit run app.py
```

Upload a ZIP of the organizer-provided `vulnerable-app` folder (or another source repository). Click **Scan Code**, inspect results, and download the report.

## How it works
1. Extracts allowlisted source files from ZIP into a temporary directory, with file-count and size limits.
2. Calls `semgrep scan --config auto --json` (static analysis, not code execution).
3. Sends up to 12 Semgrep findings to the OpenAI API for defensive explanations.
4. Displays findings and produces a Markdown report.

## Limitations
- Findings are potential issues, not confirmed vulnerabilities. Human validation is required.
- AI suggestions are not applied or tested automatically.
- AI only analyzes up to 12 findings per run to limit cost and latency.
- Semgrep rule coverage varies by language and internet availability.
- Do not upload private code to external AI services without authorization.
- This prototype is not a substitute for professional security review.

## Sample report
See `sample-reports/example-report.md` for an **illustrative template**. Replace it with a real scan report before submitting.

## Demo checklist
1. Show the upload interface.
2. Upload the TaskFlow sample ZIP.
3. Run the scanner and show file/line/severity.
4. Show an AI-generated fix recommendation.
5. Download and open the Markdown report.

## Technologies
Python, Streamlit, Semgrep, OpenAI API.

## Credits
Created as an independent hackathon prototype. Semgrep and OpenAI are third-party services/tools.
