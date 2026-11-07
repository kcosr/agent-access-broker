# OpenAPI gateway common profile

This helper compiles bounded Swagger 2.0 and OpenAPI 3.1 JSON documents into
explicit V1 operation plans and durable route guards. It validates declared
primitive path, query and request-header parameters. Request body schemas and
response body schemas are documentation; the gateway preserves streamed bytes.

Response headers are optional metadata. The selected exact status, status range
or default response may declare additional scalar headers. Invalid scalar values,
values over the 4,096-byte header cap, non-text values and invalid `Retry-After`
values are omitted without rejecting the upstream status or response body.
Repeated selected headers remain protocol errors. Host-owned framing checks, including
`Content-Length` and actual transfer-length validation, remain strict.

The helper performs no network access, authorization or credential lookup. See
the immutable wire fixtures in [src/fixtures](src/fixtures/README.md).

Build a route matcher once when publishing the validated manifest. It keeps
precompiled path segments outside the durable wire shape and selects the same
most-specific guard before checking its method and dispatch eligibility.

Forwarding reconstructs the path from that selected template. Literal segments
retain declared punctuation, including custom verbs such as `action:run`.
Captured parameter values are percent-encoded using only unreserved characters;
for example, `a@b+c` becomes `a%40b%2Bc`. Semicolons in parameter values are
rejected whether supplied raw or percent-encoded, so an upstream that strips
semicolon path parameters cannot collapse a template capture onto a guarded
literal route or a traversal segment. Declared literal punctuation remains
subject to its own source-derived route guard.
