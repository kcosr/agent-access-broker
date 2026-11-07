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
