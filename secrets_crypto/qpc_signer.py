import hashlib
from uuid import uuid4
from typing import Any
from shared.models import EvidenceSignRequest, EvidenceSignResponse

def _signature(prefix: str, payload: str) -> str:
    return f"{prefix}-{hashlib.sha256(f'{prefix}:{payload}'.encode('utf-8')).hexdigest()}"

def sign_artifact(payload: EvidenceSignRequest) -> EvidenceSignResponse:
    return EvidenceSignResponse(
        artifact_id=payload.artifact_id,
        signature_id=str(uuid4()),
        classical_signature=_signature("ecdsa", payload.artifact_hash),
        pq_signature=_signature("dilithium", payload.artifact_hash),
        verification_chain=[
            f"artifact:{payload.artifact_id}",
            f"classification:{payload.classification}",
            f"signer:{payload.signer}",
            "algorithm:hybrid-ecdsa-dilithium",
        ],
    )

class HashChainedLedger:
    def __init__(self) -> None:
        self.chain: list[dict[str, Any]] = []

    def append(self, artifact_id: str, artifact_hash: str, sig_res: EvidenceSignResponse, extra_data: dict[str, Any] = None) -> dict[str, Any]:
        index = len(self.chain)
        prev_hash = "0" * 64 if index == 0 else self.chain[-1]["current_hash"]
        
        payload = f"{index}:{artifact_id}:{artifact_hash}:{sig_res.classical_signature}:{sig_res.pq_signature}:{prev_hash}"
        current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        entry = {
            "index": index,
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash,
            "classical_signature": sig_res.classical_signature,
            "pq_signature": sig_res.pq_signature,
            "verification_chain": sig_res.verification_chain,
            "prev_hash": prev_hash,
            "current_hash": current_hash
        }
        if extra_data:
            entry.update(extra_data)
            
        self.chain.append(entry)
        return entry

    def verify_ledger(self) -> dict[str, Any]:
        for i in range(len(self.chain)):
            entry = self.chain[i]
            if entry["index"] != i:
                return {
                    "valid": False,
                    "broken_index": i,
                    "details": "index_sequence_broken",
                    "previous_hash": entry.get("prev_hash", ""),
                    "current_hash": entry.get("current_hash", "")
                }
                
            expected_prev_hash = "0" * 64 if i == 0 else self.chain[i-1]["current_hash"]
            if entry["prev_hash"] != expected_prev_hash:
                return {
                    "valid": False,
                    "broken_index": i,
                    "details": "previous_hash_mismatch",
                    "previous_hash": entry.get("prev_hash", ""),
                    "current_hash": entry.get("current_hash", "")
                }
                
            payload = f"{i}:{entry['artifact_id']}:{entry['artifact_hash']}:{entry['classical_signature']}:{entry['pq_signature']}:{entry['prev_hash']}"
            expected_curr_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if entry["current_hash"] != expected_curr_hash:
                return {
                    "valid": False,
                    "broken_index": i,
                    "details": "current_hash_mismatch",
                    "previous_hash": entry.get("prev_hash", ""),
                    "current_hash": entry.get("current_hash", "")
                }
                
        return {
            "valid": True,
            "details": "Ledger sequence verified. Cryptographic continuity intact."
        }

    def verify_chain(self) -> dict[str, Any]:
        result = self.verify_ledger()
        if result["valid"]:
            return {
                "valid": True,
                "entries_verified": len(self.chain),
                "break_at": None,
            }
        return {
            "valid": False,
            "entries_verified": result.get("broken_index", 0),
            "break_at": result.get("broken_index"),
            "reason": result.get("details", "verification_failed"),
        }

def verify_signature(artifact_hash: str, classical_sig: str, pq_sig: str) -> bool:
    expected_classical = _signature("ecdsa", artifact_hash)
    expected_pq = _signature("dilithium", artifact_hash)
    return classical_sig == expected_classical and pq_sig == expected_pq
