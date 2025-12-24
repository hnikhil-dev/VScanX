import requests
import os
import sys

# Read token from environment for safety. Provide via GITHUB_TOKEN env var when running.
TOKEN = os.environ.get("GITHUB_TOKEN")
# Allow token to be passed as the first CLI argument for convenience
if not TOKEN and len(sys.argv) > 1:
    TOKEN = sys.argv[1]

if not TOKEN:
    print("No GITHUB_TOKEN provided. Provide via GITHUB_TOKEN env var or as the first script argument.")
    sys.exit(1)
OWNER = "hnikhil-dev"
REPO = "VScanX"
BASE = "https://api.github.com"

headers = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github+json",
}

# 1) Create PR if not exists
pr_data = {
    "title": "ci: bandit triage — annotate tests & add project Bandit scan",
    "head": "ci/bandit-triage",
    "base": "main",
    "body": (
        "This PR annotates test assertions and controlled subprocess calls with `# nosec` "
        "to address Bandit findings, and adds a CI step to run Bandit only against "
        "project packages (`core`, `modules`, `reporting`) to reduce noise from third-party code and the virtualenv."
    ),
}
print('Creating PR...')
pr_url = f"{BASE}/repos/{OWNER}/{REPO}/pulls"
r = requests.post(pr_url, headers=headers, json=pr_data)
if r.status_code == 201:
    pr = r.json()
    print('PR created:', pr.get('html_url'))
elif r.status_code == 422:
    # Possibly already exists; find it
    print('PR may already exist, searching for open PR...')
    r2 = requests.get(f"{BASE}/repos/{OWNER}/{REPO}/pulls", headers=headers, params={"head": f"{OWNER}:ci/bandit-triage", "state": "open"})
    if r2.ok and r2.json():
        pr = r2.json()[0]
        print('Found existing PR:', pr.get('html_url'))
    else:
        print('Failed to create PR (422) and no open PR found. Response:', r.text)
        sys.exit(1)
else:
    print('Failed to create PR:', r.status_code, r.text)
    sys.exit(1)

# 2) Create and publish the release
# Compose release notes from RELEASE_NOTES_v2.1.0.md and CHANGELOG.md
try:
    with open('RELEASE_NOTES_v2.1.0.md', 'r', encoding='utf-8') as f:
        release_notes = f.read()
except Exception:
    release_notes = ''
try:
    with open('CHANGELOG.md', 'r', encoding='utf-8') as f:
        changelog = f.read()
except Exception:
    changelog = ''

release_body = release_notes + '\n\n' + changelog

rel_data = {
    "tag_name": "v2.1.0",
    "name": "v2.1.0",
    "body": release_body,
    "draft": False,
    "prerelease": False,
}
print('Creating release v2.1.0...')
r = requests.post(f"{BASE}/repos/{OWNER}/{REPO}/releases", headers=headers, json=rel_data)
if r.status_code in (200, 201):
    rel = r.json()
    print('Release published:', rel.get('html_url'))
else:
    print('Failed to create release:', r.status_code, r.text)
    sys.exit(1)

# 3) Upload assets (attach dist/*)
upload_url_template = rel.get('upload_url')
if not upload_url_template:
    print('No upload_url found in release response; skipping assets upload')
    sys.exit(0)

upload_url = upload_url_template.split('{')[0]
files_to_attach = [
    'dist/vscanx-2.1.0-py3-none-any.whl',
    'dist/vscanx-2.1.0.tar.gz',
]

for fname in files_to_attach:
    if not os.path.exists(fname):
        print('Missing artifact, skipping:', fname)
        continue
    print('Uploading:', fname)
    with open(fname, 'rb') as fh:
        headers_upload = {
            'Authorization': f'token {TOKEN}',
            'Content-Type': 'application/octet-stream',
        }
        params = {'name': os.path.basename(fname)}
        up = requests.post(upload_url, headers=headers_upload, params=params, data=fh)
        if up.status_code == 201:
            asset = up.json()
            print('Uploaded asset:', asset.get('browser_download_url'))
        else:
            print('Failed to upload asset:', fname, up.status_code, up.text)

# 4) Add a comment to the PR noting the release
try:
    comment_url = pr.get('comments_url')
    c = requests.post(comment_url, headers=headers, json={'body': f'Release v2.1.0 published: {rel.get("html_url")}'})
    if c.ok:
        print('Posted comment to PR')
    else:
        print('Failed to post comment to PR', c.status_code, c.text)
except Exception as e:
    print('Failed to post comment to PR', e)

print('All done. Please revoke the token when you confirm.')
