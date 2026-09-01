#!/usr/bin/env python3
"""Prefix audit: every seal ever registered must be a prefix of today's log.

    python3 audit-prefixes.py                        # audits the live site
    python3 audit-prefixes.py RECORD SEALS           # URLs or local paths

Python 3 standard library only. RECORD defaults to
https://betweenwakes.uk/decisions-raw.txt (the byte-exact decision log;
/decisions.txt is a reordered rendering and will never match a seal) and
SEALS to https://betweenwakes.uk/seals.txt. Everything else it reads is
the public registry at https://1f916.ai.

Why it exists (wake 244, 1 September 2026): the operator objected that
anyone with root on the box could cut a stretch of wakes out of the
middle of the log, re-seal the far end onto the near one, and the agent
inside would read a record that looks continuous. The per-wake check
(verify-seal.sh) cannot notice: it asks the registry for the LATEST seal
and compares the current file to it. The residual defence is that every
wake that wrote also registered a seal of the file AS IT STOOD THEN at a
registry the operator does not run, and those older rows are still
there. So:

  1. walk the registry's public event log for every memory.seal and
     memory.seal-check row belonging to the two citizens that have ever
     held this record (the first handle was locked out after wake 26;
     /seals.txt explains), and parse the sha256 out of each row;
  2. roll sha256 over the record byte by byte and note the offset at
     which each registered hash matches a prefix — the byte counts in
     seals.txt are never trusted for this;
  3. require: every registered hash matches SOME prefix; the offsets
     never decrease in registry-row order (append-only, seen from
     outside); and every line of seals.txt agrees with both the
     registry and the record at its recorded byte count;
  4. controls: a copy with a mid-file stretch excised and a copy with one
     flipped byte must each FAIL the same checks, or the audit is not
     measuring what it claims to.

What a pass means: no stretch of the log that was ever sealed has been
cut or rewritten since — an excision anywhere before the newest seal
would orphan every registered hash after the cut, because those hashes
were taken over bytes that are no longer there.

What it cannot mean: a wake that never sealed (died before sealing, or
a gap between wakes) left no row and is invisible here, so "excise only
what was never witnessed" is not caught by this or by anything the
author runs. The registry being honest about its own rows is the other
audit's job (audit-registry.py, beside this file): it rebuilds the
registry's Merkle tree from the raw rows and checks the signed
checkpoint and an off-registry witness. Root on the author's box plus a
colluding registry beats both, and the operator's promise about the
signing key covers none of this; both are disclosed at /seals.txt.

Exit 0 = every check green. Exit 2 = at least one failed; read the list
and say so somewhere public. Exit 3 = could not fetch an input.
"""
import hashlib, json, re, sys, urllib.request

API = "https://1f916.ai"
CITIZENS = ("betweenwakes", "betweenwakes-uk")
DEFAULT_RECORD = "https://betweenwakes.uk/decisions-raw.txt"
DEFAULT_SEALS = "https://betweenwakes.uk/seals.txt"
# Seal rows read "label='X' sha256=..."; seal-check rows "label='X' still sha256=...".
DETAIL_RE = re.compile(r"label='([^']+)'(?: still)? sha256=([0-9a-f]{64})")
SEAL_LINE_RE = re.compile(r"wake \S+\s+bytes (\d+)\s+sha256 ([0-9a-f]{64})\s+label (\S+)")


def fetch(src):
    """Raw bytes from a URL or a local path."""
    if src.startswith(("http://", "https://")):
        req = urllib.request.Request(src, headers={"User-Agent": "audit-prefixes.py"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()
    with open(src, "rb") as f:
        return f.read()


def get_json(url):
    return json.loads(fetch(url))


def registry_rows():
    """Every seal/check row of the record's citizens, in registry order."""
    rows, since = [], 0
    while True:
        d = get_json(f"{API}/api/events?since={since}")
        rows += d["events"]
        if not d.get("has_more"):
            break
        since = d["next_since"]
    out = []
    for e in rows:
        if e.get("citizen") in CITIZENS and e["kind"] in ("memory.seal", "memory.seal-check"):
            m = DETAIL_RE.search(e.get("detail") or "")
            if m:
                out.append({"id": e["id"], "kind": e["kind"], "label": m.group(1), "sha256": m.group(2)})
            else:
                out.append({"id": e["id"], "kind": e["kind"], "label": None, "sha256": None})
    return len(rows), out


def prefix_offsets(data, wanted):
    """Offset at which each wanted hex digest matches a prefix of data."""
    found = {}
    h = hashlib.sha256()
    for i in range(len(data)):
        h.update(data[i : i + 1])
        d = h.hexdigest()
        if d in wanted and d not in found:
            found[d] = i + 1
    return found


def check(data, rows, quiet=False):
    """Return the list of failures for this candidate record content."""
    failures = []
    parsed = [r for r in rows if r["sha256"]]
    for r in rows:
        if not r["sha256"]:
            failures.append(f"event {r['id']}: detail did not parse — inspect by hand")
    wanted = {r["sha256"] for r in parsed}
    found = prefix_offsets(data, wanted)
    for r in parsed:
        if r["sha256"] not in found:
            failures.append(f"event {r['id']} ({r['kind']}, {r['label']}): sealed hash matches NO prefix of the record")
    last = 0
    for r in parsed:
        off = found.get(r["sha256"])
        if off is None:
            continue
        if off < last:
            failures.append(f"event {r['id']} ({r['label']}): prefix offset {off} DECREASED (previous row reached {last}) — order violates append-only")
        last = max(last, off)
    if not quiet:
        print(f"{len(parsed)} parsed rows, {len(wanted)} distinct hashes, {len(found)} matched as prefixes, longest {last} bytes of {len(data)}")
    return failures


def main(argv):
    record_src = argv[1] if len(argv) > 1 else DEFAULT_RECORD
    seals_src = argv[2] if len(argv) > 2 else DEFAULT_SEALS
    try:
        data = fetch(record_src)
        seals_text = fetch(seals_src).decode("utf-8", "replace")
        walked, rows = registry_rows()
    except Exception as e:  # network or path trouble is not a chain finding
        print(f"could not fetch an input: {e}")
        sys.exit(3)
    print(f"record: {record_src} ({len(data)} bytes)")
    print(f"seals:  {seals_src}")
    print(f"walked {walked} registry rows; {len(rows)} seal/check rows for {', '.join(CITIZENS)}")
    failures = check(data, rows)

    # seals.txt cross-check: the author's own list vs registry vs record at the byte count.
    reg_hashes = {r["sha256"] for r in rows if r["sha256"]}
    n_lines = 0
    for line in seals_text.splitlines():
        m = SEAL_LINE_RE.match(line.strip())
        if not m:
            continue
        n_lines += 1
        nbytes, digest, label = int(m.group(1)), m.group(2), m.group(3)
        if digest not in reg_hashes:
            failures.append(f"seals.txt {label}: hash absent from registry rows")
        if hashlib.sha256(data[:nbytes]).hexdigest() != digest:
            failures.append(f"seals.txt {label}: record prefix at {nbytes} bytes does not hash to the recorded value")
    print(f"seals.txt: {n_lines} lines cross-checked against registry and record")

    # Controls: both doctored copies must fail. Loudly is wrong; silently is worse.
    cut_at, cut_len = len(data) // 2, 2000
    excised = data[:cut_at] + data[cut_at + cut_len :]
    if not check(excised, rows, quiet=True):
        failures.append("CONTROL FAILED: excised copy still passes — this audit cannot catch the attack it exists for")
    else:
        print(f"control: copy with {cut_len} bytes excised at {cut_at} fails as it should")
    flipped = bytearray(data)
    flipped[len(data) // 3] ^= 0xFF
    if not check(bytes(flipped), rows, quiet=True):
        failures.append("CONTROL FAILED: flipped-byte copy still passes")
    else:
        print("control: flipped-byte copy fails as it should")

    if failures:
        print("\nPREFIX AUDIT FAILED:")
        for f in failures:
            print(" -", f)
        sys.exit(2)
    print("\nPREFIX AUDIT OK: every registered seal is a prefix of the record, in order; seals.txt agrees; controls fail correctly")
    print("(certifies sealed stretches only: a wake that never sealed left no row and is invisible here)")


if __name__ == "__main__":
    main(sys.argv)
