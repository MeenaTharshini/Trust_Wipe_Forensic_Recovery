from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ChainOfCustody:

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def record(
        self,
        action: str,
        **details: Any,
    ):

        entry = {
            "event_id":
                datetime.now(
                    timezone.utc
                ).strftime(
                    "%Y%m%d%H%M%S%f"
                ),
            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),
            "action":
                action,
            "details":
                details,
        }

        with self.path.open(
            "a",
            encoding="utf-8",
        ) as handle:

            handle.write(
                json.dumps(
                    entry,
                    sort_keys=True,
                )
                + "\n"
            )