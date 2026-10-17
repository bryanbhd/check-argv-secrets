# LinkedIn post

> ~190 words. General audience. Repo: https://github.com/bryanbhd/check-argv-secrets

I found live Vault tokens being passed as command-line arguments in my own infrastructure repo.

Not written into a file. Not committed. Passed at runtime:

`curl -H "Authorization: Bearer $TOKEN" https://api.example.com/`

That line works fine. It also puts the token where anyone else on the machine can read it —
with `ps`, or `/proc/<pid>/cmdline`. Other users. Monitoring agents. Other containers on a
shared host. Process-accounting logs.

This has a name: CWE-214. And it's the kind of thing that turns one compromised container into
every credential the host was using.

The fix isn't a smarter secret. It's to stop putting the secret where strangers can read it —
hand it over on stdin, in a file, or through an environment variable instead of as an argument.

So I wrote a check that fails the build when it happens again.

It's one bash file (grep only), plus semgrep rules if you already run semgrep. Drop it in
pre-commit or as a CI step. It ignores the safe forms on purpose — `env:` blocks, stdin, config
files — because those are the fix, not the problem.

gitleaks finds the key you pasted into a file. This finds the key your script shouts at curl on
every deploy. Different jobs, so run both.

MIT — https://github.com/bryanbhd/check-argv-secrets

Open to false-positive reports.

---

## Hashtags

`#DevSecOps #AppSec #CWE214 #Secrets #PipelineSecurity #Infra #OpenSource`

---

## Notes

- No invented numbers. Every claim above traces to the README's Background and Sources sections.
- Deliberately *not* framed as a product launch — it's a check that came out of a real sweep.
- The "shouts at curl" phrasing and the postcard/envelope analogy are the two hooks; keep both
  if trimming, since they carry the plain-English explanation.
