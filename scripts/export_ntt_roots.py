"""Export falcon.py's Z_q NTT roots (n = 2..512) to JSON so the browser signer reproduces the
exact NTT ordering the on-chain Falcon verifier expects for the public key.

Usage: python -I export_ntt_roots.py --falcon-py <checkout> --out <roots.json>
"""
import argparse
import json
import sys
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--falcon-py", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    sys.path.insert(0, str(args.falcon_py))
    from ntt_constants import roots_dict_Zq  # type: ignore

    roots = {str(n): roots_dict_Zq[n] for n in (2, 4, 8, 16, 32, 64, 128, 256, 512)}
    args.out.write_text(json.dumps(roots))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
