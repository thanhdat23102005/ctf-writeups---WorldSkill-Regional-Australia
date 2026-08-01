#!/usr/bin/env python3
"""
push-to-repo.py — push a local folder to a GitHub repo in ONE commit, via the
GitHub API. No git/gh binary required (works on this VM).

Usage:
    push-to-repo.py <local-folder> [--prefix <path-in-repo>] [-m "commit message"]

Config (so you never paste a token again):
    ~/.config/ctf-writeups/token   -> your token,  chmod 600   (or env GH_TOKEN)
    ~/.config/ctf-writeups/repo    -> "owner/repo" (or env GH_REPO / --repo)

Behaviour:
    - Respects a .gitignore in the folder (simple fnmatch on relative paths).
    - Always skips .git/.
    - Uploads everything as a single commit onto the default branch (main),
      updating files that already exist.
"""
import os, sys, json, base64, fnmatch, argparse, urllib.request, urllib.error

API = "https://api.github.com"
CFG = os.path.expanduser("~/.config/ctf-writeups")


def load(name, env):
    if os.environ.get(env):
        return os.environ[env].strip()
    p = os.path.join(CFG, name)
    if os.path.exists(p):
        return open(p).read().strip()
    return None


def api(method, path, token, data=None):
    url = path if path.startswith("http") else API + path
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, method=method)
    r.add_header("Authorization", "token " + token)
    r.add_header("Accept", "application/vnd.github+json")
    try:
        with urllib.request.urlopen(r) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        sys.exit(f"GitHub API {e.code} on {method} {path}:\n{e.read().decode()}")


def gitignore_patterns(folder):
    pats = [".git", ".git/*"]
    gi = os.path.join(folder, ".gitignore")
    if os.path.exists(gi):
        for line in open(gi):
            line = line.strip()
            if line and not line.startswith("#"):
                pats.append(line.rstrip("/"))
    return pats


def ignored(rel, pats):
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p + "/*")
               or fnmatch.fnmatch(os.path.basename(rel), p) for p in pats)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--prefix", default=None, help="path inside repo (default: folder name)")
    ap.add_argument("--repo", default=None, help="owner/repo")
    ap.add_argument("-m", "--message", default=None)
    a = ap.parse_args()

    token = load("token", "GH_TOKEN")
    repo = a.repo or load("repo", "GH_REPO")
    if not token:
        sys.exit(f"No token. Put it in {CFG}/token (chmod 600) or set GH_TOKEN.")
    if not repo:
        sys.exit(f"No repo. Put owner/repo in {CFG}/repo or pass --repo.")

    folder = a.folder.rstrip("/")
    prefix = (a.prefix if a.prefix is not None else os.path.basename(folder)).strip("/")
    msg = a.message or f"Add/update {prefix}"
    pats = gitignore_patterns(folder)

    # collect files
    tree = []
    for root, dirs, fnames in os.walk(folder):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in fnames:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, folder)
            if ignored(rel, pats):
                continue
            raw = open(full, "rb").read()
            blob = api("POST", f"/repos/{repo}/git/blobs", token,
                       {"content": base64.b64encode(raw).decode(), "encoding": "base64"})
            repo_path = f"{prefix}/{rel}" if prefix else rel
            mode = "100755" if os.access(full, os.X_OK) else "100644"
            tree.append({"path": repo_path, "mode": mode, "type": "blob", "sha": blob["sha"]})
            print("  +", repo_path)

    if not tree:
        sys.exit("Nothing to upload (all files ignored?).")

    # default branch + base tree
    r = api("GET", f"/repos/{repo}", token)
    branch = r["default_branch"]
    ref = api("GET", f"/repos/{repo}/git/ref/heads/{branch}", token)
    parent = ref["object"]["sha"]
    base_tree = api("GET", f"/repos/{repo}/git/commits/{parent}", token)["tree"]["sha"]

    new_tree = api("POST", f"/repos/{repo}/git/trees", token,
                   {"base_tree": base_tree, "tree": tree})
    commit = api("POST", f"/repos/{repo}/git/commits", token,
                 {"message": msg, "tree": new_tree["sha"], "parents": [parent]})
    api("PATCH", f"/repos/{repo}/git/refs/heads/{branch}", token, {"sha": commit["sha"]})
    print(f"\nPushed to {repo}@{branch} — commit {commit['sha'][:10]}")
    print(f"https://github.com/{repo}/tree/{branch}/{prefix}")


if __name__ == "__main__":
    main()
