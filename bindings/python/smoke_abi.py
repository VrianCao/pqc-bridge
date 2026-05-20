from __future__ import annotations

import json

import pqcb


print(
    json.dumps(
        {
            "abiMajor": pqcb.abi_major_version(),
            "abiVersion": pqcb.abi_version(),
            "kemAvailable": pqcb.backend_available("ML-KEM-768"),
            "signatureAvailable": pqcb.backend_available("ML-DSA-65"),
        },
        sort_keys=True,
    )
)
