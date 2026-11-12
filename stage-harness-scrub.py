#!/usr/bin/env python3
"""stage-harness-scrub.py - write scrubbed COPIES of agent history into a staging folder. Originals are never written.

    check-memory-secrets.sh --harness all > scan.txt          # find what is flagged (counts only)
    stage-harness-scrub.py --flagged scan.txt --out ~/scrub-staging-DATE

For every flagged text file it writes a scrubbed copy under --out (same path relative to $HOME), replaces each secret
value with [REDACTED:<fingerprint>], then verifies the copy: a rescan finds no secret left and every JSON line still
parses. Nothing is swapped in; moving the staged files over the originals is a separate, deliberate step.

Skipped and reported: SQLite databases (a text replacement would corrupt them), files modified in the last
--live-minutes (a running session is still writing them), and anything not under $HOME. Output never contains a value.
The fingerprint is a keyed hash (key kept in OUT/.fpkey, mode 600), so a leaked manifest cannot be used to test guesses.
"""
import argparse, collections, hashlib, hmac, json, os, re, secrets, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NOISY = {"hex-api-key"}
SKIP_IDS = {"ssh-private-key", "pgp-private-key"}      # handled as whole blocks below
VALUE = {                                              # where the secret sits inside a match; default = whole match
    "url-cred": r'://[^:/\s"\'\\]*:(?P<v>[^@/\s"\'\\][^@/\s"\'\\]{5,})@',
    "inline-secret-key": r'[:=]\s*["\']?(?P<v>[A-Za-z0-9+/=_-]{12,})',
    "env-secret-export": r'=["\']?(?P<v>[A-Za-z0-9+/=_-]{12,})',
    "env-file-inline": r'=["\']?(?P<v>[A-Za-z0-9+/=_-]{8,})',
    "pgpassword": r'=["\']?(?P<v>[A-Za-z0-9+/=_-]{6,})',
    "mysql-pwd": r'=["\']?(?P<v>[A-Za-z0-9+/=_-]{6,})',
    "sshpass": r'=["\']?(?P<v>[A-Za-z0-9+/=_-]{6,})',
    "approle-secret-id": r'secret_id:\s*["\']?(?P<v>[A-Za-z0-9_-]{32,})',
    "bearer-token": r'Bearer (?P<v>[A-Za-z0-9._-]{20,})',
}
PRIVKEY = re.compile(r'-----BEGIN (?:(?:RSA |EC |ED25519 |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----'
                     r'[A-Za-z0-9+/=\\\s:,.-]{20,12000}?-----END [A-Z ]*-----')


HEAD = re.compile(r'-----BEGIN (?:RSA |EC |ED25519 |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----')
END = r'-----END [A-Z ]*-----'
# a BEGIN with no END (clipped output): header + base64-ish body (JSON \n \r \t escapes allowed, never \") + optional END
ORPHAN = re.compile('(?:' + HEAD.pattern + ')' + r'(?:[A-Za-z0-9+/=\s]|\\[nrt]){0,12000}(?:' + END + ')?')


def die(msg):
    print("stage-harness-scrub: " + msg, file=sys.stderr)
    sys.exit(2)


def load_patterns(script):
    pats = []
    for m in re.finditer(r'^\s*"([a-z0-9-]+)\|[^|]*\|(.*)"\s*$', script.read_text(), re.M):
        i, r = m.group(1), m.group(2)
        if i in NOISY or i in SKIP_IDS:
            continue
        r = r.replace('\\"', '"').replace("[:space:]", r"\s")
        try:
            pats.append((i, re.compile(r), re.compile(VALUE[i]) if i in VALUE else None))
        except re.error as e:
            die("cannot compile pattern %s: %s" % (i, e))
    return pats


def redaction_span(m, vre):
    text = m.group(0)
    if vre:
        v = vre.search(text)
        if v:
            return v.start("v"), v.end("v")
    return 0, len(text)


def scrub_text(text, pats, key, counts):
    def fp(value):
        return hmac.new(key, value.encode("latin-1", "replace"), hashlib.sha256).hexdigest()[:8]

    def pk(m):
        counts["private-key-block"] += 1
        return "[REDACTED-PRIVATE-KEY:%s]" % fp(m.group(0))
    text = PRIVKEY.sub(pk, text)
    def orphan(m):
        counts["private-key-orphan"] += 1
        return "[REDACTED-PRIVATE-KEY:%s]" % fp(m.group(0))
    text = ORPHAN.sub(orphan, text)
    for i, rx, vre in pats:
        def sub(m, i=i, vre=vre):
            s, e = redaction_span(m, vre)
            g = m.group(0)
            if g[s:e].startswith("[REDACTED"):
                return g
            counts[i] += 1
            return g[:s] + "[REDACTED:%s]" % fp(g[s:e]) + g[e:]
        text = rx.sub(sub, text)
    return text


def residual(text, pats):
    n = 0
    n += len(HEAD.findall(text))
    for i, rx, vre in pats:
        for m in rx.finditer(text):
            s, e = redaction_span(m, vre)
            if not m.group(0)[s:e].startswith("[REDACTED"):
                n += 1
    return n


def json_ok(path, text):
    try:
        if path.suffix == ".jsonl":
            for line in text.split("\n"):
                if line.strip():
                    json.loads(line)
        elif path.suffix == ".json":
            json.loads(text)
        return True
    except ValueError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--flagged", required=True, help="output of check-memory-secrets.sh --harness (path: [id] xN lines)")
    ap.add_argument("--out", required=True, help="new staging folder (must not exist or be empty)")
    ap.add_argument("--live-minutes", type=int, default=15, help="skip files modified more recently than this")
    ap.add_argument("--script", default=str(HERE / "check-memory-secrets.sh"), help="where the patterns are read from")
    a = ap.parse_args()

    home = Path(os.environ["HOME"]).resolve()
    out = Path(a.out).expanduser().resolve()
    if home in out.parents and any(str(out).startswith(str(home / d)) for d in (".claude", ".codex", ".local/share/opencode", ".config", ".vscode-server", ".ollama")):
        die("--out must not be inside an agent's own data folder")
    if out.exists() and any(out.iterdir()):
        die("--out exists and is not empty: " + str(out))
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out, 0o700)
    keyfile = out / ".fpkey"
    keyfile.write_bytes(secrets.token_bytes(32)); os.chmod(keyfile, 0o600)
    key = keyfile.read_bytes()

    pats = load_patterns(Path(a.script))
    files = sorted({m.group(1) for l in open(a.flagged) for m in [re.match(r"(.*): \[[a-z0-9-]+\] x\d+$", l.strip())] if m})
    manifest, tally, counts = [], collections.Counter(), collections.Counter()
    now = time.time()
    for f in files:
        p = Path(f).resolve()
        ent = {"path": str(p), "status": None}
        try:
            if home not in p.parents:
                ent["status"] = "skipped-outside-home"
            elif not p.is_file():
                ent["status"] = "skipped-missing"
            else:
                st = p.stat(); head = p.open("rb").read(16)
                ent.update(size=st.st_size, sha256_original=hashlib.sha256(p.read_bytes()).hexdigest())
                if head.startswith(b"SQLite format 3"):
                    ent["status"] = "skipped-sqlite"
                elif now - st.st_mtime < a.live_minutes * 60:
                    ent["status"] = "skipped-live"
                else:
                    c = collections.Counter()
                    text = p.read_bytes().decode("latin-1")
                    new = scrub_text(text, pats, key, c)
                    if new == text:
                        ent["status"] = "unchanged"
                    else:
                        left = residual(new, pats)
                        valid = json_ok(p, new) or not json_ok(p, text)      # fail only if the scrub broke valid JSON
                        if left or not valid:
                            ent.update(status="failed", residual=left, json_valid=valid)
                        else:
                            dest = out / p.relative_to(home)
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            dest.write_bytes(new.encode("latin-1")); os.chmod(dest, 0o600)
                            ent.update(status="staged", replaced=dict(c), sha256_staged=hashlib.sha256(dest.read_bytes()).hexdigest(),
                                       staged_path=str(dest))
                            counts.update(c)
        except OSError as e:
            ent["status"] = "error:%s" % type(e).__name__
        manifest.append(ent); tally[ent["status"]] += 1
    mf = out / "manifest.json"
    mf.write_text(json.dumps({"made": time.strftime("%Y-%m-%dT%H:%M:%S"), "files": manifest}, indent=1)); os.chmod(mf, 0o600)

    print("stage-harness-scrub: %d flagged file(s) considered" % len(files))
    for k, v in sorted(tally.items()):
        print("  %-22s %d" % (k, v))
    print("  replacements by pattern: " + ", ".join("%s=%d" % kv for kv in counts.most_common()))
    print("  staging folder: %s (manifest.json inside; originals untouched)" % out)
    sys.exit(1 if tally.get("failed") or any(str(s).startswith("error") for s in tally) else 0)


if __name__ == "__main__":
    main()
