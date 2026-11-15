# Comparison example fixtures

These original Apache-2.0 inventories use inventory schema 1 and invented paths,
sizes and hashes. They describe no external firmware or file contents.

The candidate inventory represents an executable rebuild accompanied by an
unrelated configuration edit. `ExampleCompare` in `internal/delta` compares
the pair without a policy, so both changes are unexpected. A planned change
becomes expected only when a matching policy is applied.
