# Test support fixtures

These files are test-only and are embedded into the `test-support` feature of
this package; nothing reads them from the filesystem at test time.

- `outbound-tls-ca.pem`: a disposable self-signed P-256/SHA-256 test CA
  (`CN=Broker outbound test CA a`), valid from 2020-01-01 through 2120-01-01.
  Its private key is not committed. `TestHost` clients trust only this
  certificate. Never use it to trust a deployed service.
