"""CDF Hackathon: Find -> Fix -> Fortify security reviewer."""
import io
import os
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import streamlit as st
from dotenv import load_dotenv
from scanner import scan, ALLOWED, EXCLUDED, MAX_FILES, MAX_FILE_BYTES
from ai_analyzer import explain
from report_generator import generate

load_dotenv()
st.set_page_config(page_title='CDF AI Security Reviewer', page_icon='🛡️', layout='wide')
st.title('🛡️ CDF AI Security Reviewer')
st.caption('FIND vulnerabilities • FIX with AI recommendations • FORTIFY with a downloadable report')
st.info('Upload a ZIP of source code. Files are scanned statically; uploaded code is never executed.')
source = st.file_uploader('Upload source code ZIP', type=['zip'])
use_ai = st.checkbox('Generate AI explanations (requires OPENAI_API_KEY)', value=bool(os.getenv('OPENAI_API_KEY')))

def extract_safe(upload, dest):
    content = upload.getvalue()
    if len(content) > 12_000_000:
        raise ValueError('ZIP exceeds 12 MB')
    count = 0
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            name = member.filename.replace('\\', '/')
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or ':' in name or any(part in EXCLUDED for part in path.parts):
                continue
            if path.suffix.lower() not in ALLOWED:
                continue
            if member.file_size > MAX_FILE_BYTES:
                continue
            count += 1
            if count > MAX_FILES:
                raise ValueError(f'Too many source files (maximum {MAX_FILES})')
            target = (dest / Path(*path.parts)).resolve()
            if not target.is_relative_to(dest.resolve()):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as stream, target.open('wb') as out:
                # Bound decompressed size, including malformed archive metadata.
                chunk = stream.read(MAX_FILE_BYTES + 1)
                if len(chunk) > MAX_FILE_BYTES:
                    target.unlink(missing_ok=True)
                    continue
                out.write(chunk)
    if count == 0:
        raise ValueError('No supported source files in ZIP')
    return count

if st.button('🔍 Scan Code', type='primary', disabled=source is None):
    try:
        with st.spinner('Scanning source code...'):
            with tempfile.TemporaryDirectory() as tmp:
                count = extract_safe(source, Path(tmp))
                findings, errors = scan(Path(tmp))
        analyzed = []
        if use_ai and findings:
            with st.spinner('Generating AI recommendations...'):
                try:
                    analyzed = explain(findings)
                except Exception as exc:
                    st.warning(f'AI analysis unavailable: {exc}. Scanner findings are still shown.')
        report = generate(findings, analyzed, errors)
        st.session_state['results'] = (findings, analyzed, errors, report, count)
    except Exception as exc:
        st.error(f'Scan failed: {exc}')

if 'results' in st.session_state:
    findings, analyzed, errors, report, count = st.session_state['results']
    a, b, c = st.columns(3)
    a.metric('Files scanned', count)
    b.metric('Potential findings', len(findings))
    c.metric('AI-reviewed findings', len(analyzed))
    if errors:
        st.warning(f'Semgrep reported {len(errors)} warnings/errors. Check configuration and scan coverage.')
    if findings:
        st.dataframe([{k: f[k] for k in ('severity', 'file', 'line', 'rule', 'message')} for f in findings], use_container_width=True)
        lookup = {(f['file'], f['line'], f['rule']): f for f in analyzed}
        for f in findings:
            with st.expander(f'{f["severity"]} — {f["file"]}:{f["line"]} — {f["rule"]}'):
                st.write(f['message'])
                ai = lookup.get((f['file'], f['line'], f['rule']))
                if ai:
                    st.markdown('**Risk:** ' + ai['risk'])
                    st.markdown('**Suggested fix:** ' + ai['fix'])
                    if ai['secure_example']:
                        st.code(ai['secure_example'])
                else:
                    st.caption('AI explanation not available for this finding.')
    else:
        st.success('No findings from the selected Semgrep rules. This is not a security guarantee.')
    st.download_button('⬇️ Download Markdown Security Report', report, file_name='cdf-security-report.md', mime='text/markdown')
    st.markdown('### Report preview')
    st.markdown(report)
