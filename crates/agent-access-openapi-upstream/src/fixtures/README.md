# Unified import fixtures

`openapi31-baseline-source.json` and `openapi31-baseline-contracts.json` freeze
real adapter output from commit `b1b94045a2d29ad55d834b4730668efffecba617` before
the two-reader refactor. The latter contains exact serialized action and preview
manifest bytes for bearer and header-key execution, JSON object and array bodies,
bodyless operations, local schema closure, parameter overrides and response plans.
Do not regenerate these to accommodate parser changes.

`swagger2-synthetic.json` is the supplied, wholly synthetic Swagger 2.0 sample,
retained byte for byte (SHA-256
`074c6f1826bd9200c3b608a611c9ab8d3bc82e391a41854d9ea672516e7f7c87`). It has
15 operations across 14 paths: nine JSON bodies, three scalar form bodies and
three bodyless operations. Its declared and used tags agree. The extra focused
tests supply a reachable `minItems` constraint, string path parameters, namespace
collisions and isolated invalid references. A string schema with mixed-type enum
`["Y", 2]` admits `"Y"` and rejects `2` through ordinary type intersection.
