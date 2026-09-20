# sshkeyaudit

Scans an `authorized_keys` file, a single `.pub` file, or a directory of
`.pub` files, and flags weak SSH key types and sizes: RSA under 2048
bits, DSA (deprecated entirely regardless of size), and keys with no
comment. There's no dominant standalone Rust tool for this — the usual
approach is a shell one-liner piping `ssh-keygen -lf` output through
`awk`, or trusting whatever your config-management tool happens to
enforce.

## Usage

```bash
sshkeyaudit ~/.ssh/authorized_keys
sshkeyaudit ~/.ssh                    # scans every *.pub file in the directory
sshkeyaudit --strict ~/.ssh           # also fail on Warning-level findings
```

```
$ sshkeyaudit ~/.ssh
[OK]   /home/user/.ssh/id_ed25519.pub:1 - Ed25519 (256 bits) comment: user@laptop
[WEAK] /home/user/.ssh/old_key.pub:1 - RSA (1024 bits) comment: user@old-server
       - RSA key is 1024 bits, below the 2048-bit minimum

2 key(s) scanned: 1 ok, 0 warning(s), 1 weak
```

Exit code `0` if nothing is flagged `WEAK` (or, with `--strict`, nothing
flagged `WARN` either); `1` otherwise — scriptable as a pre-deploy or CI
check against a fleet's `authorized_keys` files.

## How it works

No SSH or crypto crate is used to parse the keys. Each key line is
base64-decoded and then walked field-by-field against the SSH public-key
wire format (RFC 4253 §6.6 / RFC 4251 §5: length-prefixed `string` and
`mpint` fields) — enough to read out the algorithm and, for RSA and DSA,
the modulus size, without needing to parse or validate the key material
itself the way an actual SSH implementation would. Ed25519 and ECDSA
sizes are fixed by algorithm (256/384/521), so those are looked up by
name rather than computed from the blob.

`authorized_keys` line parsing tokenizes on whitespace and scans for a
recognized key-type token (`ssh-rsa`, `ssh-dss`, `ssh-ed25519`,
`ecdsa-sha2-nistp256/384/521`), so a line prefixed with options
(`no-pty,no-agent-forwarding ssh-rsa AAAA...`) is still parsed correctly
— the options themselves are only checked for *presence*, not
interpreted.

## Status: built, 38 unit tests passing, weak/strong classification live-verified against real key material

- **38 unit tests** (`cargo test --lib`): SSH wire-format field reading
  (`read_u32`/`read_string`, including truncated-input errors), `mpint`
  bit-length arithmetic (zero, no sign-padding byte, with sign-padding
  byte, a realistic 2048-bit-modulus byte shape, a realistic 1024-bit
  shape, multiple leading zero bytes), key-type detection for all 6
  recognized algorithms plus the `Unknown` fallback, line tokenizing
  (plain `.pub` lines, multi-word comments, missing comments,
  `authorized_keys` lines with a leading options field, blank/`#`-comment
  lines skipped, malformed lines rejected), the weak/warn/ok verdict
  logic (DSA always weak regardless of stated bit count, RSA below/at/above
  the 2048 threshold including the exact 2047/2048 boundary, missing
  comment is a `Warning` that never gets swallowed by or masks a `Weak`
  verdict, unrecognized key types are a `Warning` not a silent pass), and
  file/directory scanning (a malformed line doesn't abort the rest of the
  file, non-`.pub` files in a directory are ignored, blank/comment lines
  produce no findings).
- **Live-verified with real `ssh-keygen`-generated keys**, cross-checked
  against `ssh-keygen -lf` itself (not just against this tool's own
  logic): generated `ssh-keygen -t rsa -b 1024`, `-t rsa -b 4096`,
  `-t rsa -b 2048` (with an empty comment via `-C ""`), and
  `-t ed25519` into a scratch directory, then ran `sshkeyaudit` against
  it. Bit counts this tool reported (1024 / 4096 / 2048 / 256) matched
  `ssh-keygen -lf`'s own reported bit counts exactly for every key.
  Verdicts were correct: the 1024-bit RSA key came back `WEAK` ("below
  the 2048-bit minimum"), the 4096- and 2048-bit RSA keys and the
  Ed25519 key came back `OK` except the empty-comment 2048-bit key,
  which correctly came back `WARN` for the missing comment and nothing
  else. Also tested a real `authorized_keys`-style file: one line with a
  `no-pty,no-agent-forwarding` options prefix ahead of the weak RSA key
  was still correctly parsed and flagged, and a clean two-key file (the
  4096-bit RSA key plus the Ed25519 key) scanned as `2 ok, 0 warning(s),
  0 weak` with exit code `0`. `--strict` was verified separately: a
  directory containing only the missing-comment key exits `0` normally
  but `1` under `--strict`.
- **DSA verification, and a real limitation this surfaced**: this
  sandbox's OpenSSH build (`OpenSSH_10.5p1`) has removed DSA key
  *generation* from `ssh-keygen` entirely — `ssh-keygen -t dsa` fails
  outright with `unknown key type dsa`, and there's no DSA host key on
  this machine either (`/etc/ssh/*.pub` has only RSA, ECDSA, and
  Ed25519). So instead of `ssh-keygen`, real DSA key material was
  generated with `openssl dsaparam`/`gendsa` (a genuine 1024-bit DSA
  keypair, not synthetic bytes), and its `P`/`Q`/`G`/pub values —
  extracted from `openssl dsa -pubin -text -noout`'s own output — were
  assembled into a real `ssh-dss`-format wire blob and base64-encoded by
  hand, since no tool on this box will do that conversion. Feeding the
  result to `sshkeyaudit` correctly reported `DSA (1024 bits)` and
  `WEAK` with the deprecation reason. As an extra data point on just how
  deprecated DSA now is: `ssh-keygen -lf` itself refuses to even *read*
  the resulting `.pub` file ("is not a public key file") on this
  OpenSSH version — `sshkeyaudit`'s independent wire-format parser
  (it doesn't shell out to `ssh-keygen` for anything) still handles it
  fine, and the 1024-bit figure it reports was independently
  cross-checked against `openssl`'s own `P:` field byte length.

**Not done / deliberately deferred**: no support for `sk-ssh-ed25519@openssh.com`/
`sk-ecdsa-sha2-nistp256@openssh.com` (FIDO/U2F-backed keys) or
`ssh-rsa-cert-v01@openssh.com`-style certificates — only the 6 plain key
types are recognized, anything else is reported as `Unknown` with a
`Warning` rather than assessed; `authorized_keys` option *values*
containing quoted spaces (`command="echo hi"`) can be split across
tokens by the whitespace tokenizer — key-type detection and
`has_options` are unaffected since neither depends on option content,
but this tool never attempts to reconstruct or validate the option
string itself; no recursive directory scanning (a `.ssh` directory
holding subdirectories of `.pub` files won't be walked); no check for
duplicate keys across files, revoked/`KnownHosts`-style files, or key
expiry (OpenSSH's newer certificate `valid-before` field) — this is
purely a per-key type/size/comment audit.
