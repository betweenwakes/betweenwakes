#!/usr/bin/env python3
"""verify.py — verifier for a sealed-record (SPEC.md, version 1).

    python3 verify.py [--held OLDER.seals] [--explorer] <record>.seals
    python3 verify.py [--held OLDER.seals] [--explorer] https://host/path/<record>.seals

Prints the custody line first, then one row per layer, then a table of
what each layer proves and does not prove. There is no badge and no
pass/fail verdict, but there is a machine-readable exit status so that a
monitor can be built on it (Nick, by mail, wake 222):

    0  ran to the end, no layer reported a finding
    1  ran to the end, at least one layer reported a FINDING (the record
       is shorter than a seal, a prefix hash mismatches, the chain is
       broken, a signature fails, a timestamp proof fails, or a held
       copy of the seals file is not a prefix of the current one)
    2  could not run (missing file, malformed seals file, fetch failed)

"Finding", not "bad": the output says what the finding is, and degraded
states (unsigned, pending, absent, not checked) are printed but are not
findings. Earlier drafts exited 0 whenever the verifier ran, on the
argument that a non-zero exit is a badge by another name; that left
nobody able to build a witness on it without parsing prose, which is
the weaker position.

With a URL, the verifier fetches the seals file, then the record from
its `record-url`, `allowed_signers` and every `seals/<n>.sig` and
`seals/<n>.ots` from beside it, into a temporary directory, and verifies
those. With --held, an older copy of the seals file is compared against
the current one: its seal lines must be a prefix of the current seal
lines. That comparison is the one thing here that can notice deletion
from the END of the seals file, and only a party who kept the older
copy can make it — a witness is exactly a cron job that fetches, holds,
and compares.

Needs: python3 (stdlib only). Uses `ssh-keygen -Y verify` if present,
`ots verify` if present; when either is missing the corresponding layer
says "not checked" with the reason. Never silently skips a layer.
"""
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

SPEC_VERSION = "1"
NAMESPACE = "sealed-record-v1"
REQUIRED_KEYS = ("sealed-record", "record", "signer", "namespace", "custody")

SEAL_RE = re.compile(
    r"^seal (\d+) bytes (\d+) sha256 ([0-9a-f]{64}) prev ([0-9a-f]{64}|-) at "
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$"
)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


class Seal:
    def __init__(self, n, length, digest, prev, at, raw):
        self.n = n
        self.length = length
        self.digest = digest
        self.prev = prev
        self.at = at
        self.raw = raw  # bytes of the line including its LF


FINDINGS = []  # one short string per definite finding; decides exit 1 vs 0


def finding(text):
    FINDINGS.append(text)


def die(msg):
    print("CANNOT VERIFY: " + msg)
    print("(this is a failure of the verifier's inputs, not a finding about the record)")
    sys.exit(2)


def fetch(url, optional=False):
    """GET a URL as bytes. Returns None for a 404 when optional, dies otherwise."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, headers={"User-Agent": "sealed-record-verify/1"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if optional and e.code == 404:
            return None
        die("fetch %s: HTTP %d" % (url, e.code))
    except (urllib.error.URLError, OSError) as e:
        die("fetch %s: %s" % (url, e))


def fetch_set(seals_url):
    """Fetch a seals file and everything beside it into a temp dir; return
    (dir, local seals path). Prints what it fetched: these lines are the
    verifier's own record of which bytes it examined."""
    import urllib.parse
    base_url = seals_url.rsplit("/", 1)[0] + "/"
    d = tempfile.mkdtemp(prefix="sealed-record-")
    seals_bytes = fetch(seals_url)
    seals_name = urllib.parse.unquote(seals_url.rsplit("/", 1)[1]) or "record.seals"
    seals_path = os.path.join(d, seals_name)
    with open(seals_path, "wb") as f:
        f.write(seals_bytes)
    print("fetched: %s (%d bytes)" % (seals_url, len(seals_bytes)))
    header, seals = parse_seals_file(seals_path)
    if not header.get("record-url"):
        die("seals file has no record-url; cannot fetch the record")
    if not header.get("record"):
        die("seals file has no record name")
    record = fetch(header["record-url"])
    with open(os.path.join(d, header["record"]), "wb") as f:
        f.write(record)
    print("fetched: %s (%d bytes) as %s" % (header["record-url"], len(record), header["record"]))
    allowed = fetch(base_url + "allowed_signers", optional=True)
    if allowed is not None:
        with open(os.path.join(d, "allowed_signers"), "wb") as f:
            f.write(allowed)
        print("fetched: %sallowed_signers (%d bytes)" % (base_url, len(allowed)))
    else:
        print("fetched: %sallowed_signers — not there (404)" % base_url)
    os.mkdir(os.path.join(d, "seals"))
    got = {"sig": 0, "ots": 0}
    for s in seals:
        for ext in ("sig", "ots"):
            b = fetch("%sseals/%d.%s" % (base_url, s.n, ext), optional=True)
            if b is not None:
                with open(os.path.join(d, "seals", "%d.%s" % (s.n, ext)), "wb") as f:
                    f.write(b)
                got[ext] += 1
    print("fetched: %sseals/ — %d .sig, %d .ots of %d seals" % (base_url, got["sig"], got["ots"], len(seals)))
    print()
    return d, seals_path


def compare_held(held_path, current_path):
    """--held: the older copy's seal lines must be a prefix of the current
    seal lines. The header is compared separately and only observed: it is
    unsigned prose and witness lines may legitimately be appended to it."""
    with open(held_path, "rb") as f:
        held = f.read()
    with open(current_path, "rb") as f:
        cur = f.read()
    if b"\n\n" not in held:
        die("held copy has no blank line separating header from seals")
    hh, hb = held.split(b"\n\n", 1)
    ch, cb = cur.split(b"\n\n", 1)
    if hh != ch:
        print("held copy: header differs from the current one (unsigned prose; witness lines")
        print("  may be appended over time — an observation, not a finding; read both)")
    if hb == cb:
        print("held copy: %s — identical seal lines to the current file" % held_path)
        return
    if cb.startswith(hb):
        added = cb[len(hb):].count(b"\n")
        print("held copy: %s — is a prefix of the current file; %d seal line(s) added since"
              % (held_path, added))
        return
    n = 0
    while n < min(len(hb), len(cb)) and hb[n] == cb[n]:
        n += 1
    held_line = hb[:n].count(b"\n") + 1
    print()
    print("*** HELD COPY DIVERGES ***")
    print("*** The seal lines in %s are not a prefix of the current seals file." % held_path)
    print("*** First difference at seal-body byte %d, seal line %d of the held copy." % (n, held_line))
    if len(cb) < len(hb) and hb.startswith(cb):
        print("*** The current file is the held one with %d line(s) removed from the END."
              % (hb[len(cb):].count(b"\n")))
        print("*** This is the end-deletion signature that no other layer can see.")
    else:
        print("*** A seal line the witness saw has been changed or replaced.")
    print()
    finding("held copy of the seals file is not a prefix of the current one")


def parse_seals_file(path):
    with open(path, "rb") as f:
        data = f.read()
    if b"\n\n" not in data:
        die("seals file has no blank line separating header from seals")
    head, body = data.split(b"\n\n", 1)
    header = {}
    witnesses = []
    for line in head.split(b"\n"):
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            die("header line is not UTF-8")
        if ":" not in text:
            die("header line without ':' — %r" % text)
        k, v = text.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k == "witness":
            witnesses.append(v)
        else:
            header[k] = v
    header["_witnesses"] = witnesses
    seals = []
    for raw in body.split(b"\n"):
        if raw == b"":
            continue
        raw_lf = raw + b"\n"
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            die("seal line is not ASCII: %r" % raw[:60])
        m = SEAL_RE.match(text)
        if not m:
            die("seal line does not parse: %r" % text)
        seals.append(Seal(int(m.group(1)), int(m.group(2)), m.group(3),
                          m.group(4), m.group(5), raw_lf))
    return header, seals


EXPLORERS = ("https://blockstream.info/api", "https://mempool.space/api")


def explorer_block(height):
    """Ask two public block explorers for block <height>; return
    (merkle_root, unix_time, note) if both agree, else (None, None, note).
    Third parties, chosen by the verifier, trusted only jointly and only
    when --explorer was given: this is a substitute for a Bitcoin node,
    and the output says so."""
    import json
    import urllib.request
    seen = []
    for base in EXPLORERS:
        try:
            h = urllib.request.urlopen(base + "/block-height/%d" % height, timeout=20).read().decode().strip()
            b = json.load(urllib.request.urlopen(base + "/block/" + h, timeout=20))
            seen.append((base, b["merkle_root"].lower(), int(b["timestamp"])))
        except Exception as e:  # network, parse, key
            seen.append((base, None, str(e)))
    ok = [x for x in seen if x[1]]
    if len(ok) < 2:
        return None, None, "explorer lookup incomplete: " + "; ".join("%s: %s" % (b, m if m else t) for b, m, t in seen)
    if ok[0][1] != ok[1][1]:
        return None, None, "explorers DISAGREE on block %d merkle root: %s" % (height, "; ".join("%s %s" % (b, m) for b, m, _ in ok))
    return ok[0][1], ok[0][2], "%s agree" % " and ".join(b.split("//")[1].split("/")[0] for b, _, _ in ok)


def run(cmd, stdin_bytes=None):
    try:
        p = subprocess.run(cmd, input=stdin_bytes, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, str(e)
    out = (p.stdout + p.stderr).decode("utf-8", "replace").strip()
    return p.returncode, out


def key_fingerprints(allowed_path):
    """(SHA256:... fingerprint, principal) per key line of an allowed_signers file."""
    out = []
    with open(allowed_path, "rb") as f:
        for line in f.read().split(b"\n"):
            t = line.decode("utf-8", "replace").strip()
            if not t or t.startswith("#"):
                continue
            parts = t.split()
            blob = None
            for i, tok in enumerate(parts):
                if tok.startswith("ssh-") or tok.startswith("ecdsa-") or tok.startswith("sk-"):
                    if i + 1 < len(parts):
                        blob = parts[i + 1]
                    break
            if blob is None:
                out.append(("(unparsed line)", t[:60]))
                continue
            try:
                raw = base64.b64decode(blob)
            except Exception:
                out.append(("(bad base64)", parts[0]))
                continue
            fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
            out.append((fp, parts[0]))
    return out


def main():
    argv = sys.argv[1:]
    held = None
    explorer = False
    if "--explorer" in argv:
        explorer = True
        argv = [a for a in argv if a != "--explorer"]
    if len(argv) >= 2 and argv[0] == "--held":
        held = argv[1]
        argv = argv[2:]
    if len(argv) != 1:
        print(__doc__)
        sys.exit(2)
    target = argv[0]
    if target.startswith("http://") or target.startswith("https://"):
        base, seals_path = fetch_set(target)
    else:
        seals_path = target
        if not os.path.isfile(seals_path):
            die("no such file: %s" % seals_path)
        base = os.path.dirname(os.path.abspath(seals_path))
    if held is not None and not os.path.isfile(held):
        die("no such held copy: %s" % held)
    header, seals = parse_seals_file(seals_path)

    rows = []  # (layer, result, proves, does_not_prove)

    # 0. custody — first line of output, always.
    custody = header.get("custody", "").strip()
    if not custody:
        print("custody: MISSING")
        print("The seals file has no `custody` line. That line states who besides the")
        print("signer can reach the private key; a record whose author will not say")
        print("this does not conform to sealed-record v1. Nothing else is checked.")
        sys.exit(2)
    print("custody: " + custody)
    print("  (quoted from the seals-file header, which no seal or signature covers;")
    print("   the author's statement, not a checked fact — c28454)")
    print()
    rows.append(("0 custody", "printed above (quoted, unsigned)",
                 "nothing — it is the author's own statement",
                 "that the statement is true, or even that it is the signer's: the header is unsigned; you weigh it"))

    # 1. format
    missing = [k for k in REQUIRED_KEYS if not header.get(k)]
    problems = []
    if missing:
        problems.append("missing header keys: " + ", ".join(missing))
    if header.get("sealed-record") != SPEC_VERSION:
        problems.append("sealed-record version %r, this verifier knows %r"
                        % (header.get("sealed-record"), SPEC_VERSION))
    if header.get("namespace", NAMESPACE) != NAMESPACE:
        problems.append("namespace %r, expected %r" % (header.get("namespace"), NAMESPACE))
    if not seals:
        problems.append("no seal lines")
    for i, s in enumerate(seals):
        if s.n != i + 1:
            problems.append("seal numbering: expected %d, found %d "
                            "(a gap here is also exactly what a seal line removed "
                            "from the middle of this file looks like; a format "
                            "failure is not a clean bill)" % (i + 1, s.n))
        if i and s.length <= seals[i - 1].length:
            problems.append("seal %d bytes %d not greater than seal %d bytes %d"
                            % (s.n, s.length, seals[i - 1].n, seals[i - 1].length))
    if problems:
        for p in problems:
            print("format: " + p)
        die("seals file does not conform; findings above are about the seals file, not the record. "
            "This is not a clean bill for the record: nothing below ran.")
    print("format: ok — %d seal(s), header complete" % len(seals))
    rows.append(("1 format", "ok", "the seals file is well-formed", "anything about the record"))

    # signer set: say which file was used, where it came from, and what keys
    # it holds. The trust base of the signature layer is this file, and it is
    # covered by no seal or signature (c28454).
    allowed = os.path.join(base, "allowed_signers")
    if os.path.isfile(allowed):
        print("signers: %s — read from beside the seals file; covered by no seal or signature"
              % os.path.relpath(allowed))
        for fp, principal in key_fingerprints(allowed):
            print("  %s  %s" % (fp, principal))
    else:
        print("signers: no allowed_signers file beside the seals file")

    # record
    record_path = os.path.join(base, header["record"])
    if not os.path.isfile(record_path):
        die("record file not found: %s" % record_path)
    with open(record_path, "rb") as f:
        record = f.read()
    largest = seals[-1]
    print("record: %s, %d bytes present, largest seal covers %d bytes"
          % (header["record"], len(record), largest.length))
    if header.get("record-url"):
        if target.startswith("http"):
            print("record-url: %s  (fetched above; the bytes verified are that response)" % header["record-url"])
        else:
            print("record-url: %s  (this run read the local file, not the URL; give the seals")
            print("  file's URL instead of a path to fetch and verify what is actually served)")

    # 2. length against largest seal — the loud case
    if len(record) < largest.length:
        print()
        print("*** RECORD SHORTENED ***")
        print("*** seal %d covers %d bytes; only %d bytes are present. ***"
              % (largest.n, largest.length, len(record)))
        print("*** A record cannot honestly be shorter than its own seal. This is the")
        print("*** deletion signature. The remaining layers run on the bytes present,")
        print("*** but this headline stands regardless of what they say.")
        print()
        finding("record shortened below seal %d" % largest.n)
        rows.append(("2 length", "RECORD SHORTENED by %d bytes" % (largest.length - len(record)),
                     "—", "—  (definite: the record was cut below a seal the author published)"))
    else:
        print("length: ok — record is not shorter than its largest seal")
        rows.append(("2 length", "ok", "the record was not cut below its last seal",
                     "that no seal was removed from the END of the seals file (see below)"))

    # 3. prefix hashes
    print()
    first_mismatch = None
    n_ok = 0
    for s in seals:
        if s.length > len(record):
            print("prefix seal %d: NOT PRESENT (needs %d bytes, have %d)" % (s.n, s.length, len(record)))
            continue
        h = sha256(record[: s.length])
        if h == s.digest:
            n_ok += 1
            print("prefix seal %d: matched  (%d bytes, %s… claimed at %s)" % (s.n, s.length, s.digest[:12], s.at))
        else:
            if first_mismatch is None:
                first_mismatch = s
            print("prefix seal %d: MISMATCH (%d bytes; sealed %s…, computed %s…)"
                  % (s.n, s.length, s.digest[:12], h[:12]))
    for i in range(1, len(seals)):
        if seals[i].at < seals[i - 1].at:
            print("note: seal %d claims %s, earlier than seal %d's %s — file order is the chain, "
                  "`at` is testimony; this is an observation, not a failure"
                  % (seals[i].n, seals[i].at, seals[i - 1].n, seals[i - 1].at))
    if first_mismatch is None:
        rows.append(("3 prefixes", "%d/%d matched" % (n_ok, len(seals)),
                     "no byte covered by a matching seal has changed since that seal",
                     "anything about bytes after the last matching seal"))
    else:
        finding("prefix mismatch from seal %d" % first_mismatch.n)
        lo = 0
        for s in seals:
            if s.n < first_mismatch.n:
                lo = s.length
        rows.append(("3 prefixes", "MISMATCH from seal %d" % first_mismatch.n,
                     "—",
                     "—  (definite: bytes in [%d, %d) differ from what was sealed; "
                     "everything after is unverified)" % (lo, first_mismatch.length)))

    # 4. chain
    print()
    chain_ok = True
    for i, s in enumerate(seals):
        expect = "-" if i == 0 else sha256(seals[i - 1].raw)
        if s.prev == expect:
            print("chain seal %d: ok" % s.n)
        else:
            chain_ok = False
            finding("chain broken at seal %d" % s.n)
            print("chain seal %d: BROKEN (prev %s…, previous line hashes to %s…)"
                  % (s.n, s.prev[:12], expect[:12]))
    rows.append(("4 chain", "ok" if chain_ok else "BROKEN",
                 "no seal line was removed from the MIDDLE of the seals file",
                 "that none was removed from the END; that is witnessed, not proven"))

    # 5. signatures
    print()
    signer = header["signer"]
    sshkeygen = shutil.which("ssh-keygen")
    sig_summary = []
    if not sshkeygen:
        reason = "ssh-keygen not on this machine"
    elif not os.path.isfile(allowed):
        reason = "no allowed_signers file beside the seals file"
    else:
        reason = None
    if reason:
        print("signatures: not checked — " + reason)
        rows.append(("5 signatures", "not checked: " + reason, "nothing — layer did not run", "everything this layer would have"))
    else:
        counts = {"verified": 0, "FAILED": 0, "unsigned": 0}
        for s in seals:
            sig = os.path.join(base, "seals", "%d.sig" % s.n)
            if not os.path.isfile(sig):
                counts["unsigned"] += 1
                print("signature seal %d: unsigned (no %s)" % (s.n, os.path.relpath(sig, base)))
                continue
            rc, out = run([sshkeygen, "-Y", "verify", "-f", allowed, "-I", signer,
                           "-n", NAMESPACE, "-s", sig], stdin_bytes=s.raw)
            if rc == 0:
                counts["verified"] += 1
                print("signature seal %d: verified (%s)" % (s.n, out.splitlines()[0] if out else "ok"))
            else:
                counts["FAILED"] += 1
                finding("signature of seal %d failed" % s.n)
                print("signature seal %d: FAILED (%s)" % (s.n, out.replace("\n", " | ")))
        summary = ", ".join("%d %s" % (v, k) for k, v in counts.items() if v)
        rows.append(("5 signatures", summary,
                     "verified seals were published by the holder of the key in allowed_signers",
                     "who that holder is, or that only the signer holds the key (see custody); "
                     "that allowed_signers is the author's rather than substituted beside a substituted record; "
                     "an unsigned seal is degraded, not forged"))

    # 6. timestamps
    print()
    ots = shutil.which("ots")
    if not ots:
        print("timestamps: not checked — ots not installed on this machine")
        rows.append(("6 timestamps", "not checked: ots not installed", "nothing — layer did not run", "everything this layer would have"))
    else:
        counts = {"anchored": 0, "anchored (header not checked)": 0, "pending": 0, "failed": 0, "absent": 0}
        if explorer:
            print("timestamps: --explorer given — where no Bitcoin node answers, block headers are checked against %s"
                  % " and ".join(b.split("//")[1].split("/")[0] for b in EXPLORERS))
        else:
            print("timestamps: block headers are checked only if a local Bitcoin node answers; --explorer substitutes two public explorers")
        block_cache = {}
        for s in seals:
            proof = os.path.join(base, "seals", "%d.ots" % s.n)
            if not os.path.isfile(proof):
                counts["absent"] += 1
                print("timestamp seal %d: absent" % s.n)
                continue
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(s.raw)
                tmp = tf.name
            try:
                rc, out = run([ots, "verify", "-f", tmp, proof])
                # No Bitcoin node on this machine (wake 223: every anchored
                # proof of the dogfood read `failed` here, because `ots
                # verify` checks block headers only against a local node).
                # Re-run with Bitcoin disabled: ots then still checks that
                # the proof commits to the line's bytes, and prints the
                # block height and merkle root it would have checked.
                no_node = rc != 0 and "could not connect to bitcoin node" in (out or "").lower()
                if no_node:
                    rc2, out2 = run([ots, "--no-bitcoin", "verify", "-f", tmp, proof])
                    out = (out or "") + "\n" + (out2 or "")
            finally:
                os.unlink(tmp)
            low = (out or "").lower()
            m = re.search(r"bitcoin block (\d+) attests existence as of (.+)", out or "", re.I)
            claims = re.findall(r"bitcoin block (\d+) has merkleroot ([0-9a-f]+)", out or "", re.I)
            if rc == 0 and "success" in low:
                counts["anchored"] += 1
                if m:
                    state = "anchored %s %s" % (m.group(1), m.group(2).strip())
                else:
                    state = "anchored (height and time not parsed from ots output; raw lines below)"
            elif no_node and claims:
                # The proof commits the line to a Bitcoin block header; whether
                # that header is really in the chain was NOT checked here.
                height, root = min((int(h), r.lower()) for h, r in claims)
                if explorer:
                    if height not in block_cache:
                        block_cache[height] = explorer_block(height)
                    e_root, e_time, note = block_cache[height]
                    if e_root == root:
                        counts["anchored"] += 1
                        state = "anchored %d %s (block header checked against explorers, not a node: %s)" % (
                            height, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e_time)), note)
                    elif e_root is None:
                        counts["anchored (header not checked)"] += 1
                        state = "anchored (header not checked) — proof commits to block %d merkle root %s…; %s" % (height, root[:12], note)
                    else:
                        counts["failed"] += 1
                        finding("timestamp proof of seal %d names block %d with merkle root %s… but explorers report %s…" % (s.n, height, root[:12], e_root[:12]))
                        state = "failed (merkle root does not match the explorers' block %d)" % height
                else:
                    counts["anchored (header not checked)"] += 1
                    state = ("anchored (header not checked) — proof commits to block %d merkle root %s…; "
                             "no Bitcoin node here; re-run with --explorer or check that block yourself" % (height, root[:12]))
            # Precedence: `A or B or C and D` parses as `A or B or (C and D)`;
            # an earlier draft wrote it that way and a calendar-only proof that
            # returned 0 fell through to "failed" (Nick, wake 222). Parenthesised.
            elif ("pending" in low or "not enough confirmations" in low or "calendar" in low) and rc != 0:
                counts["pending"] += 1
                state = "pending (calendar attestation only — a server's word, not a block)"
            else:
                counts["failed"] += 1
                finding("timestamp proof of seal %d failed" % s.n)
                state = "failed"
            print("timestamp seal %d: %s" % (s.n, state))
            for line in (out or "").splitlines():
                print("    ots: " + line)
        summary = ", ".join("%d %s" % (v, k) for k, v in counts.items() if v)
        proves = "an anchored seal existed before roughly its block's time (hours of slack)"
        if counts["anchored (header not checked)"]:
            proves += ("; for 'header not checked' only that the proof commits the line to a named block header — "
                       "whether that header is in the Bitcoin chain was not checked by this run")
        if explorer and counts["anchored"]:
            proves += "; 'checked against explorers' rests on two third-party block explorers agreeing, not on a node"
        rows.append(("6 timestamps", summary, proves,
                     "precise time; that a pending proof will ever anchor; anything for absent ones; "
                     "that a 'header not checked' block exists"))

    # 7. unsealed tail
    print()
    if len(record) > largest.length:
        extra = len(record) - largest.length
        print("tail: %d byte(s) after seal %d are not covered by any seal" % (extra, largest.n))
        rows.append(("7 tail", "%d unsealed byte(s)" % extra, "nothing about them",
                     "anything about them"))
    else:
        print("tail: none — record ends at seal %d" % largest.n)
        rows.append(("7 tail", "none", "—", "—"))

    # table
    print()
    print("layer          result")
    print("-------------  ------------------------------------------------------------")
    for layer, result, _, _ in rows:
        print("%-13s  %s" % (layer, result))
    print()
    print("what a good result proves / does not prove")
    for layer, _, proves, notproves in rows:
        print("  %s" % layer)
        print("      proves:         %s" % proves)
        print("      does not prove: %s" % notproves)
    print()
    print("Not proven by any layer here: that nothing was deleted from the END of the")
    print("seals file together with the record (only a holder of an older copy can")
    print("notice — append-only is witnessed, not proven); that the record's contents")
    print("are true; who the signer is; that the key was used only by the signer.")
    print("Quoted from the inputs, not derived by this verifier: the custody line,")
    print("record-url, the witness list, the signer name, and every seal's `at` (a")
    print("claim inside a signed line: the signer's clock, not a check). Derived:")
    print("seal count, byte counts, prefix hashes, chain, signature results, tail.")
    print("With the private key, everything above except anchored timestamps and")
    print("witness copies can be regenerated honestly-signed for a different record.")
    if header["_witnesses"]:
        print("Witness copies the author says exist:")
        for w in header["_witnesses"]:
            print("  " + w)
    else:
        print("The author names no witness copies.")
    if held is not None:
        print()
        compare_held(held, seals_path)
    print()
    if FINDINGS:
        print("findings: %d — %s" % (len(FINDINGS), "; ".join(FINDINGS)))
        print("exit 1 (ran to the end; at least one layer reported a finding)")
        sys.exit(1)
    print("findings: none")
    print("exit 0 (ran to the end; no layer reported a finding — see the table for what that does not mean)")
    sys.exit(0)


if __name__ == "__main__":
    main()
