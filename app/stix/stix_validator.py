from __future__ import annotations

from typing import Any, Dict, List, Tuple


class STIX21Validator:
    """Validates STIX 2.1 JSON bundle structure, required fields, and SDO/SRO relationships."""

    REQUIRED_BUNDLE_FIELDS = ["type", "id", "spec_version", "objects"]
    VALID_SDO_TYPES = {
        "threat-actor",
        "attack-pattern",
        "indicator",
        "observed-data",
        "malware",
        "vulnerability",
        "identity",
        "infrastructure",
        "relationship",
        "sighting",
    }

    def validate_bundle(self, bundle: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        # Check bundle root keys
        for field in self.REQUIRED_BUNDLE_FIELDS:
            if field not in bundle:
                errors.append(f"Missing required bundle field: '{field}'")

        if bundle.get("type") != "bundle":
            errors.append(f"Invalid bundle type: expected 'bundle', got '{bundle.get('type')}'")

        if bundle.get("spec_version") != "2.1":
            errors.append(f"Invalid spec_version: expected '2.1', got '{bundle.get('spec_version')}'")

        objects = bundle.get("objects", [])
        if not isinstance(objects, list):
            errors.append("Bundle 'objects' must be a list")
            return False, errors

        object_ids = set()
        for i, obj in enumerate(objects):
            if not isinstance(obj, dict):
                errors.append(f"Object at index {i} is not a dictionary")
                continue

            obj_type = obj.get("type")
            obj_id = obj.get("id")

            if not obj_type or obj_type not in self.VALID_SDO_TYPES:
                errors.append(f"Object {i} has invalid or unknown type: '{obj_type}'")

            if not obj_id or not obj_id.startswith(f"{obj_type}--"):
                errors.append(f"Object {i} has invalid STIX ID format: '{obj_id}' for type '{obj_type}'")
            else:
                object_ids.add(obj_id)

            if obj.get("spec_version") != "2.1":
                errors.append(f"Object '{obj_id}' missing or invalid spec_version '2.1'")

        # Validate relationship references
        for obj in objects:
            if obj.get("type") == "relationship":
                src = obj.get("source_ref")
                tgt = obj.get("target_ref")
                rel_type = obj.get("relationship_type")

                if not src or src not in object_ids:
                    errors.append(f"Relationship '{obj.get('id')}' source_ref '{src}' not found in bundle objects")
                if not tgt or tgt not in object_ids:
                    errors.append(f"Relationship '{obj.get('id')}' target_ref '{tgt}' not found in bundle objects")
                if not rel_type:
                    errors.append(f"Relationship '{obj.get('id')}' missing relationship_type")

        valid = len(errors) == 0
        return valid, errors
