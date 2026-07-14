from secrets_crypto.evidence_signer import sign_artifact
from shared.models import EvidenceSignRequest, EvidenceSignResponse

def sign(payload: EvidenceSignRequest) -> EvidenceSignResponse:
    return sign_artifact(payload)
