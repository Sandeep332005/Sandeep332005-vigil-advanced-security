import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secrets_crypto.evidence_signer import sign_artifact
from shared.models import EvidenceSignRequest


class EvidenceSignerTests(unittest.TestCase):
    def test_sign_artifact_returns_hybrid_metadata(self) -> None:
        response = sign_artifact(
            EvidenceSignRequest(
                artifact_id="case-123",
                artifact_hash="abc123",
                artifact_type="case-bundle",
                classification="restricted",
                signer="soc-automation",
            )
        )
        self.assertTrue(response.classical_signature.startswith("ecdsa-"))
        self.assertTrue(response.pq_signature.startswith("dilithium-"))


if __name__ == "__main__":
    unittest.main()
