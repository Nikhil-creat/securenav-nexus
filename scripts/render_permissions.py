"""Extract one grant from the multi-grant permissions template for a given enclave.

Usage: render_permissions.py <template.xml> <grant_name>
Prints a standalone, schema-valid permissions document to stdout.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET


def render(template: str, grant_name: str) -> str:
    tree = ET.parse(template)
    root = tree.getroot()
    grants = root.findall("permissions/grant")
    selected = [g for g in grants if g.get("name") == grant_name]
    if not selected:
        raise SystemExit(f"grant '{grant_name}' not found in {template}")
    dds = ET.Element("dds", {"xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                             "xsi:noNamespaceSchemaLocation": "http://www.omg.org/spec/DDS-Security/20170801/omg_shared_ca_permissions.xsd"})
    perms = ET.SubElement(dds, "permissions")
    perms.append(selected[0])
    ET.indent(dds)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(dds, encoding="unicode")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    sys.stdout.write(render(sys.argv[1], sys.argv[2]))
