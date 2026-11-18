These certificates and private keys are synthetic, public test fixtures only.
Never use them for a deployed listener.

The EC and RSA leaf certificates are signed by the included test CA and cover
`localhost`, `broker.example.test`, `127.0.0.1`, and `::1`. Their validity interval
is 2000-01-01 through 2120-01-01. The rotated leaf has a distinct EC key. The CA
signing key was discarded. PKCS#8, RSA PKCS#1, and EC SEC1 files exercise the
supported unencrypted key encodings; tests copy them to owner-only files before
loading them. Tests do not invoke certificate-generation tools.
