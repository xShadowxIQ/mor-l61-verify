#!/usr/bin/env python3
"""L61: byte-level comparison of compiled SessionRouter vs the live Base facet.

Runs in GitHub Actions after `forge build`. Reads the forge artifact, fetches the
deployed runtime code with eth_getCode at a pinned block, and classifies every
differing byte as (a) an external-library link slot, (b) the trailing CBOR
metadata blob, or (c) an unexplained logic difference.
"""
import json, os, re, sys, urllib.request
from Crypto.Hash import keccak

FACET = "0x3a3952f0e57b343f00b31f7da039ef16389b7260"
BLOCK = 61444135
ART = "out/SessionRouter.sol/SessionRouter.json"
RPC = os.environ.get("RPC_URL", "https://base-rpc.publicnode.com")
PH = re.compile(r"__\$[0-9a-fA-F]{34}\$__")


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def kh(b):
    k = keccak.new(digest_bits=256)
    k.update(b)
    return "0x" + k.hexdigest()


def meta(b):
    n = int.from_bytes(b[-2:], "big")
    return b[-2 - n:-2], n


def ranges_overlap(a_start, a_len, b_start, b_len):
    return a_start < b_start + b_len and b_start < a_start + a_len


def main():
    art = json.load(open(ART))
    db = art["deployedBytecode"]
    obj = db["object"]
    lrefs = db.get("linkReferences") or art.get("linkReferences") or {}
    irefs = db.get("immutableReferences") or art.get("immutableReferences") or {}

    slots = []
    for src, libs in lrefs.items():
        for lib, entries in libs.items():
            for e in entries:
                slots.append({"start": int(e["start"]), "length": int(e["length"]),
                              "source": src, "library": lib})
    slots.sort(key=lambda s: s["start"])

    ph_found = [{"start": m.start() // 2, "length": (m.end() - m.start()) // 2}
                for m in PH.finditer(obj)]
    clean_hex = PH.sub(lambda m: "0" * len(m.group(0)), obj)
    compiled = bytes.fromhex(clean_hex)

    code = rpc("eth_getCode", [FACET, hex(BLOCK)])["result"][2:]
    onchain = bytes.fromhex(code)

    comp_meta, comp_meta_len = meta(compiled)
    live_meta, live_meta_len = meta(onchain)
    meta_start = len(onchain) - (live_meta_len + 2)

    # full comparison
    full_first = next((i for i, (a, b) in enumerate(zip(compiled, onchain)) if a != b), None)
    full_eq = compiled == onchain and comp_meta == live_meta

    # mask ONLY link slots on both sides
    c_masked = bytearray(compiled)
    o_masked = bytearray(onchain)
    for s in slots:
        a, n = s["start"], s["length"]
        c_masked[a:a + n] = b"\x00" * n
        o_masked[a:a + n] = b"\x00" * n
    masked_diffs = [i for i, (a, b) in enumerate(zip(c_masked, o_masked)) if a != b]
    masked_eq = (len(c_masked) == len(o_masked)) and not masked_diffs

    # classify every masked diff
    unexplained = [i for i in masked_diffs
                   if not any(ranges_overlap(i, 1, s["start"], s["length"]) for s in slots)
                   and not (i >= meta_start)]
    in_link = [i for i in masked_diffs
               if any(ranges_overlap(i, 1, s["start"], s["length"]) for s in slots)]
    in_meta = [i for i in masked_diffs if i >= meta_start]

    # logic-only: mask link slots AND the whole trailing metadata blob
    c_logic = bytearray(compiled)
    o_logic = bytearray(onchain)
    for s in slots:
        a, n = s["start"], s["length"]
        c_logic[a:a + n] = b"\x00" * n
        o_logic[a:a + n] = b"\x00" * n
    c_meta_start = len(c_logic) - (comp_meta_len + 2)
    o_meta_start = len(o_logic) - (live_meta_len + 2)
    c_logic[c_meta_start:] = b"\x00" * (len(c_logic) - c_meta_start)
    o_logic[o_meta_start:] = b"\x00" * (len(o_logic) - o_meta_start)
    logic_eq = c_logic == o_logic
    logic_first = next((i for i, (a, b) in enumerate(zip(c_logic, o_logic)) if a != b), None)

    out = {
        "facet": FACET,
        "block": BLOCK,
        "rpc": RPC,
        "variant": "SessionRouter",
        "artifact": ART,
        "deployed_len": len(onchain),
        "compiled_len": len(compiled),
        "deployed_sha": kh(onchain),
        "compiled_sha_raw": kh(compiled),
        "link_references": lrefs,
        "link_slots": slots,
        "placeholders_found": ph_found,
        "immutable_references": irefs,
        "equal_full": full_eq,
        "first_diff_full": full_first,
        "equal_after_masking_links": masked_eq,
        "first_diff_after_masking_links": masked_diffs[0] if masked_diffs else None,
        "masked_diff_count": len(masked_diffs),
        "masked_diffs_in_link_slots": len(in_link),
        "masked_diffs_in_metadata": len(in_meta),
        "masked_diffs_unexplained": len(unexplained),
        "unexplained_offsets": unexplained[:20],
        "equal_logic_mask_links_and_metadata": logic_eq,
        "first_diff_logic": logic_first,
        "metadata_equal": comp_meta == live_meta,
        "compiled_metadata_len": comp_meta_len,
        "deployed_metadata_len": live_meta_len,
        "compiled_metadata_hex": comp_meta.hex(),
        "deployed_metadata_hex": live_meta.hex(),
        "metadata_start_offset": meta_start,
        "compiled_metadata_start_offset": len(compiled) - (comp_meta_len + 2),
        "deployed_metadata_start_offset": meta_start,
    }
    json.dump(out, open("comparison_result.json", "w"), indent=2)

    p = print
    p("=== L61 BYTE-LEVEL COMPARISON ===")
    p(f"facet={FACET} block={BLOCK} rpc={RPC}")
    p(f"deployed_len={out['deployed_len']}  compiled_len={out['compiled_len']}")
    p(f"deployed_sha (keccak256) = {out['deployed_sha']}")
    p(f"compiled_sha (raw, placeholders as zero) = {out['compiled_sha_raw']}")
    p(f"link_slots={json.dumps(slots)}")
    p(f"placeholders_found={ph_found}")
    p(f"immutable_references={json.dumps(irefs)}")
    p(f"equal_full={full_eq}  first_diff_full={full_first}")
    p(f"equal_after_masking_links={masked_eq}  first_diff_masked={out['first_diff_after_masking_links']}")
    p(f"masked_diff_count={len(masked_diffs)} in_link={len(in_link)} in_metadata={len(in_meta)} unexplained={len(unexplained)}")
    p(f"unexplained_offsets(first20)={unexplained[:20]}")
    p(f"equal_logic_mask_links_and_metadata={logic_eq}  first_diff_logic={logic_first}")
    p(f"metadata_equal={comp_meta == live_meta}  compiled_meta_len={comp_meta_len} deployed_meta_len={live_meta_len} meta_start={meta_start}")
    p(f"deployed_metadata_hex={live_meta.hex()}")
    p(f"compiled_metadata_hex={comp_meta.hex()}")
    if not logic_eq:
        p("*** LOGIC BYTES DIFFER OUTSIDE LINK SLOTS AND METADATA ***")
        sys.exit(2)
    p("RESULT: logic bytes identical once documented link slots and trailing metadata are excluded")


if __name__ == "__main__":
    main()
