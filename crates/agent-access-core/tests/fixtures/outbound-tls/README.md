# Outbound TLS test certificates

These disposable test CAs and localhost leaf certificates are valid from
2020-01-01 through 2120-01-01. They use P-256/SHA-256. Both leaves cover
`localhost` and `127.0.0.1`; each is signed only by its corresponding CA.
Only the synthetic leaf private keys are committed. Never use these fixtures
for deployed services. Tests require neither OpenSSL nor network CA services.
