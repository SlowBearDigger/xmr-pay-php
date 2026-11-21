# Changelog

## [0.2.0] - 2026-11-21

- Require complete block and transaction evidence from all configured nodes before advancing scan state.
- Handle authenticated nodes and bound transport response sizes; reject incomplete or inconsistent evidence.
- Document node availability and scan-state requirements. Every configured node must answer; remove or repair unavailable nodes before expecting settlement.
- Reject noncanonical Base58 blocks and keep scalar reduction independent of ambient BCMath scale, using the corrected MoneroPHP codecs.
