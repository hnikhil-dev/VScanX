import requests, sys
TOKEN = sys.argv[1]
headers = {'Authorization': f'token {TOKEN}', 'Accept': 'application/vnd.github+json'}
url = 'https://api.github.com/repos/hnikhil-dev/VScanX/issues/1/comments'
body = {'body': 'CI update: Excluded `tests` from Bandit scan to avoid false positives on test asserts (B101). This keeps Bandit focused on production code (`core`, `modules`, `reporting`).'}
r = requests.post(url, headers=headers, json=body)
print(r.status_code, r.ok)
print(r.text)
