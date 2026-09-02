from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class RecoveredArtifact:

    artifact_id: str
    artifact_type: str

    source_offset: int
    source_end: int

    size: int

    output_path: str

    sha256: str

    validation_status: str

    confidence: int

    recovery_method: str = "SIGNATURE_CARVING"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)