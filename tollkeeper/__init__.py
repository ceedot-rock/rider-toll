"""Agent Rider toll-keeper platform.

Modules:
    envelope   - signed attestation envelope (canonical JSON -> SHA-256 -> ES256)
    identity   - (module A, separate builder)
    reputation - (module A, separate builder)
    billing    - (module B, separate builder)
    grants     - module C: Warrant-compatible scoped delegation grants
    oracle     - module D: CuNi/Chamber verification oracle
    bonds      - (module E, separate builder)
    memory     - (module F, separate builder)

Money rule (from envelope.py): amounts inside envelopes are integer
micro-USDC ("uusdc"; 1 USDC = 1_000_000 uusdc). Floats are refused.
"""

__version__ = "0.1.0"
