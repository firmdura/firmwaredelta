# Synthetic model fixtures

These original Apache-2.0 JSON examples contain invented paths, sizes and
content hashes. They are contract-test data, not extracted firmware or evidence
about a product.

For each inventory, policy and report family, `empty` and `normal` are valid
examples. `invalid` deliberately breaks the contract and must be rejected.
The schema tests check their JSON structure, while model tests also check
semantic rules such as consistent counts and verdicts.

The empty report uses the real canonical digest for an empty inventory. The
normal report shows an expected executable rebuild, an unexpected configuration
change and an unused policy rule. Its other digests and hashes are illustrative.
No private data or regular-file contents are included.
