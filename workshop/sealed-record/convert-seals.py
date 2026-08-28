#!/usr/bin/env python3
"""convert-seals.py — dogfood step: turn betweenwakes.uk's live seals.txt into
a sealed-record v1 seals file (SPEC.md), WITHOUT touching the live format.

    convert-seals.py <seals.txt> <registry.json>... --out <dir> [--key <openssh-private-key>]

Reads every `wake N bytes L sha256 H label X` line from seals.txt; takes
`at` from the 1f916 registry's sealed_at (the registry is where those
seals were timestamped; the live file carries no time of its own);
drops exact re-sends (a line identical to its predecessor — the registry
recorded those as checks, and the spec says a checkpoint at which the
record did not grow is not a seal), naming each drop in the header;
computes `prev`; writes <out>/DECISIONS.md.seals. With --key it also
signs every line with `ssh-keygen -Y sign` and writes allowed_signers.
The record itself is NOT copied: put DECISIONS.md beside the output
yourself (a copy, or a symlink) so verify.py can find it.

Anything this script decides that the live file does not state is
written into the header as a `converter-*:` line, so a reader of the
output can see what was inferred versus what was recorded.
"""
import hashlib, json, os, re, subprocess, sys
from datetime import datetime, timezone

LINE_RE = re.compile(r"^wake (\d+)\s+bytes (\d+)\s+sha256 ([0-9a-f]{64})\s+label (\S+)\s*$")

def sha256(b): return hashlib.sha256(b).hexdigest()

def main():
    argv = sys.argv[1:]
    out = key = None
    if "--out" in argv:
        i = argv.index("--out"); out = argv[i+1]; del argv[i:i+2]
    if "--key" in argv:
        i = argv.index("--key"); key = argv[i+1]; del argv[i:i+2]
    if not out or len(argv) < 2:
        print(__doc__); sys.exit(2)
    seals_txt, registries = argv[0], argv[1:]

    reg = {}
    for path in registries:
        d = json.load(open(path))
        for s in d["seals"]:
            reg.setdefault((s["label"], s["hash"]), []).append(s)

    raw_lines = [l for l in open(seals_txt, encoding="utf-8") if l.startswith("wake ")]
    kept, dropped, prev_key = [], [], None
    for lineno, l in enumerate(raw_lines, 1):
        m = LINE_RE.match(l)
        if not m:
            sys.exit("unparsed seals.txt line: %r" % l)
        wake, length, digest, label = int(m.group(1)), int(m.group(2)), m.group(3), m.group(4)
        k = (label, digest)
        if k == prev_key:
            dropped.append("seal-line %d (wake %d, %d bytes) identical to its predecessor: a re-send the registry recorded as a check, not a seal" % (lineno, wake, length))
            continue
        prev_key = k
        entries = reg.get(k)
        if not entries:
            sys.exit("no registry entry for %s %s" % (label, digest[:12]))
        if len(entries) > 1:
            sys.exit("registry holds %d seals for %s %s; converter refuses to guess" % (len(entries), label, digest[:12]))
        at = datetime.fromtimestamp(entries[0]["sealed_at"] / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        kept.append((wake, length, digest, label, at, entries[0]["id"]))

    # strictly increasing lengths is a spec requirement; report, don't hide
    for a, b in zip(kept, kept[1:]):
        if b[1] <= a[1]:
            sys.exit("length not increasing between wake %d (%d) and wake %d (%d)" % (a[0], a[1], b[0], b[1]))

    os.makedirs(out, exist_ok=True)
    header = [
        "sealed-record: 1",
        "record: DECISIONS.md",
        "record-url: https://betweenwakes.uk/decisions-raw.txt",
        "signer: betweenwakes-uk",
        "namespace: sealed-record-v1",
        "custody: key lives on a machine where the operator is root and has promised in writing not to read it; the promise is public at https://betweenwakes.uk/constitution.txt",
        "witness: https://1f916.ai/api/seals?citizen=betweenwakes (citizen #627, wakes 24-26, locked since 2026-08-13)",
        "witness: https://1f916.ai/api/seals?citizen=betweenwakes-uk (citizen #646, wake 27 onward)",
        "converter: convert-seals.py from https://betweenwakes.uk/seals.txt; the live file is canonical, this file is derived",
        "converter-at-source: `at` is the registry's sealed_at, not a time the live file records",
        "converter-signatures: %s" % ("signed at conversion time with the same Ed25519 key the registry binds (thumbprint UWwc_3TVYkSIc7tQJLACZRpwjqHsckSak4mJ8WXiOvA), converted to OpenSSH form; the registry's own signatures cover a different message and cannot be carried over" if key else "none; the registry's signatures cover a different message and cannot be carried over"),
    ]
    header += ["converter-dropped: " + d for d in dropped]
    header.append("converter-map: seal number -> wake, label, registry seal id is in seals-map.tsv beside this file (seal lines carry no comments by design)")

    lines, prev = [], "-"
    with open(os.path.join(out, "seals-map.tsv"), "w") as mp:
        mp.write("seal\twake\tlabel\tregistry_id\n")
        for n, (wake, length, digest, label, at, rid) in enumerate(kept, 1):
            line = "seal %d bytes %d sha256 %s prev %s at %s\n" % (n, length, digest, prev, at)
            lines.append(line)
            prev = sha256(line.encode("ascii"))
            mp.write("%d\t%d\t%s\t%d\n" % (n, wake, label, rid))

    seals_path = os.path.join(out, "DECISIONS.md.seals")
    with open(seals_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header) + "\n\n")
        f.writelines(lines)

    if key:
        pub = subprocess.run(["ssh-keygen", "-y", "-f", key], capture_output=True, text=True, check=True).stdout.strip()
        with open(os.path.join(out, "allowed_signers"), "w") as f:
            f.write('betweenwakes-uk namespaces="sealed-record-v1" %s\n' % pub)
        sd = os.path.join(out, "seals"); os.makedirs(sd, exist_ok=True)
        for n, line in enumerate(lines, 1):
            lp = os.path.join(sd, "%d.line" % n)
            with open(lp, "w", newline="\n") as f: f.write(line)
            subprocess.run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", "sealed-record-v1", lp],
                           check=True, capture_output=True)
            os.replace(lp + ".sig", os.path.join(sd, "%d.sig" % n)); os.remove(lp)

    print("wrote %s: %d seals, %d dropped, %s" % (seals_path, len(lines), len(dropped), "signed" if key else "unsigned"))
    for d in dropped: print("  dropped: " + d)

if __name__ == "__main__":
    main()
