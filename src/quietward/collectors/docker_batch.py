from __future__ import annotations

import json
from typing import Iterable

from .models import ContainerRecord
from .parsers import parse_docker_inspect_output


def parse_docker_inspect_batch_output(
    text: str,
    bases: Iterable[ContainerRecord],
) -> tuple[ContainerRecord, ...]:
    """Apply ordered Docker inspect objects to their bounded base records.

    The read-only collector invokes Docker with one ID list. Docker preserves
    argument order for formatted inspect output; malformed/missing rows fail
    closed to the corresponding base record instead of borrowing another row.
    """

    base_values = tuple(bases)
    objects: list[dict[str, object]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            raw = json.loads(stripped)
        except json.JSONDecodeError:
            objects.append({})
            continue
        if isinstance(raw, dict):
            objects.append(raw)
        elif isinstance(raw, list):
            objects.extend(item for item in raw if isinstance(item, dict))
        else:
            objects.append({})

    result: list[ContainerRecord] = []
    for index, base in enumerate(base_values):
        if index >= len(objects) or not objects[index]:
            result.append(base)
            continue
        result.append(
            parse_docker_inspect_output(
                json.dumps(objects[index], separators=(",", ":")),
                base,
            )
        )
    return tuple(result)
