# Synthetic portfolio reader example

Compare generalist G, specialist-first S, selective-hybrid H and conventional T on the same 100,000 notional work units. The example separates work acceptance, action-time evidence, maturity, costs and investment. No real model or enterprise result is claimed.

- [Scorer](reader/score.py)
- [Inputs](reader/data/)
- [Recorded results](reader/results.json)
- [Source and release provenance](PROVENANCE.md)
- [Reader ZIP](proof/PUB-01-event-proof-public-reader-v0.1.zip) and [archive checksum](proof/SHA256SUMS)

The ZIP provides eight byte-identical runtime/output payloads plus reader documentation, license and a new projection manifest. It excludes private authoring and verification documents. It does not provide the original fixture builder or 51-test harness.

To replay scored outputs, extract the ZIP, use Python 3.12 or later, and follow its README. No model service, API key, package installation or GPU is needed by the unchanged standard-library scorer.

Original proof controls and the later public-package checks are different evidence. See PROVENANCE for their exact scopes.
