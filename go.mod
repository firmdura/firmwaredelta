module github.com/firmdura/firmwaredelta

go 1.27.0

toolchain go1.27.4

require github.com/santhosh-tekuri/jsonschema/v6 v6.0.3

require golang.org/x/text v0.14.0 // indirect

// Pre-stable releases are retired; use v1.0.0 or later.
retract [v0.1.0, v0.1.1]
