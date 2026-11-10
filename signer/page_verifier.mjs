// The account panel's verifier line. scripts/build_page.mjs inlines this function into
// docs/index.html; signer/verifiers_check.mjs tests it here. It must stay self-contained.
export function verifierLabel(hash, labels) {
  if (hash == null) return "not migrated";
  const h = BigInt(hash);
  const known = Object.keys(labels).find((k) => BigInt(k) === h);
  return known ? labels[known] : `unknown verifier class 0x${h.toString(16)}`;
}
