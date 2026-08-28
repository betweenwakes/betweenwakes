#!/usr/bin/env python3
"""verify.py — verifier for a sealed-record (SPEC.md, version 1).

    python3 verify.py <record>.seals

Prints the custody line first, then one row per layer, then a table of
what each layer proves and does not prove. There is no badge and no
pass/fail verdict. Exit status 0 means the verifier ran to the end;
exit status 2 means it could not run (missing file, malformed seals
file). What it FOUND is in the output, not the exit code.

Needs: python3 (stdlib only). Uses `ssh-keygen -Y verify` if present,
`ots verify` if present; when either is missing the corresponding layer
says "not checked" with the reason. Never silently skips a layer.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

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


def die(msg):
    print("CANNOT VERIFY: " + msg)
    print("(this is a failure of the verifier's inputs, not a finding about the record)")
    sys.exit(2)


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


def run(cmd, stdin_bytes=None):
    try:
        p = subprocess.run(cmd, input=stdin_bytes, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, str(e)
    out = (p.stdout + p.stderr).decode("utf-8", "replace").strip()
    return p.returncode, out


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    seals_path = sys.argv[1]
    if not os.path.isfile(seals_path):
        die("no such file: %s" % seals_path)
    base = os.path.dirname(os.path.abspath(seals_path))
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
    print()
    rows.append(("0 custody", "printed above",
                 "nothing — it is the author's own statement",
                 "that the statement is true; you weigh it"))

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
        print("record-url: %s  (this verifier read the local file, not the URL)" % header["record-url"])

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
            print("prefix seal %d: matched  (%d bytes, %s… at %s)" % (s.n, s.length, s.digest[:12], s.at))
        else:
            if first_mismatch is None:
                first_mismatch = s
            print("prefix seal %d: MISMATCH (%d bytes; sealed %s…, computed %s…)"
                  % (s.n, s.length, s.digest[:12], h[:12]))
    if first_mismatch is None:
        rows.append(("3 prefixes", "%d/%d matched" % (n_ok, len(seals)),
                     "no byte covered by a matching seal has changed since that seal",
                     "anything about bytes after the last matching seal"))
    else:
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
            print("chain seal %d: BROKEN (prev %s…, previous line hashes to %s…)"
                  % (s.n, s.prev[:12], expect[:12]))
    rows.append(("4 chain", "ok" if chain_ok else "BROKEN",
                 "no seal line was removed from the MIDDLE of the seals file",
                 "that none was removed from the END; that is witnessed, not proven"))

    # 5. signatures
    print()
    signer = header["signer"]
    allowed = os.path.join(base, "allowed_signers")
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
                print("signature seal %d: FAILED (%s)" % (s.n, out.replace("\n", " | ")))
        summary = ", ".join("%d %s" % (v, k) for k, v in counts.items() if v)
        rows.append(("5 signatures", summary,
                     "verified seals were published by the holder of the key in allowed_signers",
                     "who that holder is, or that only the signer holds the key (see custody); "
                     "an unsigned seal is degraded, not forged"))

    # 6. timestamps
    print()
    ots = shutil.which("ots")
    if not ots:
        print("timestamps: not checked — ots not installed on this machine")
        rows.append(("6 timestamps", "not checked: ots not installed", "nothing — layer did not run", "everything this layer would have"))
    else:
        counts = {"anchored": 0, "pending": 0, "failed": 0, "absent": 0}
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
            finally:
                os.unlink(tmp)
            low = (out or "").lower()
            if rc == 0 and "success" in low:
                counts["anchored"] += 1
                state = "anchored"
            elif "pending" in low or "not enough confirmations" in low or "calendar" in low and rc != 0:
                counts["pending"] += 1
                state = "pending (calendar attestation only — a server's word, not a block)"
            else:
                counts["failed"] += 1
                state = "failed"
            print("timestamp seal %d: %s" % (s.n, state))
            for line in (out or "").splitlines():
                print("    ots: " + line)
        summary = ", ".join("%d %s" % (v, k) for k, v in counts.items() if v)
        rows.append(("6 timestamps", summary,
                     "an anchored seal existed before roughly its block's time (hours of slack)",
                     "precise time; that a pending proof will ever anchor; anything for absent ones"))

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
    if header["_witnesses"]:
        print("Witness copies the author says exist:")
        for w in header["_witnesses"]:
            print("  " + w)
    else:
        print("The author names no witness copies.")
    sys.exit(0)


if __name__ == "__main__":
    main()
