export function sellerEvidenceByAddress(bundle, entries) {
  const byClaim = new Map();
  for (const entry of entries) {
    const claimId = entry.claim.claimId.toLowerCase();
    if (byClaim.has(claimId)) throw new Error(`${claimId}: duplicate evidence entry`);
    byClaim.set(claimId, entry);
  }
  const result = new Map();
  for (const claim of bundle.claims) {
    const entry = byClaim.get(claim.claimId.toLowerCase());
    if (!entry) throw new Error(`${claim.claimId}: approved evidence is missing`);
    for (const subject of claim.subjects) {
      const seller = subject.toLowerCase();
      if (result.has(seller)) {
        throw new Error(`${seller}: exactly one evidence bundle is supported per seller proof`);
      }
      result.set(seller, entry);
    }
  }
  return result;
}

export function singleEvidenceEntry(entry, seller) {
  if (!entry || Array.isArray(entry) || !entry.kind || !entry.witnessPath) {
    throw new Error(`${seller}: exactly one evidence bundle is required`);
  }
  return entry;
}
