"""Record the installed runtime dependency closure after an intentional update.

Run pip install -r requirements.txt first, then this script, pip check,
pip-audit -r requirements-runtime.lock --no-deps --disable-pip, and the tests.
The runtime lock excludes development/auditing tools.
"""
from importlib.metadata import distribution
from pathlib import Path
from packaging.requirements import Requirement
import argparse
import json
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hashes", action="store_true", help="Resolve release artifact SHA256s from official PyPI")
    args = parser.parse_args()
    seen = {}
    def collect(name):
        package = distribution(name)
        key = package.metadata["Name"].lower().replace("_", "-")
        if key in seen:
            return
        seen[key] = (package.metadata["Name"], package.version)
        for text in package.requires or []:
            requirement = Requirement(text)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                collect(requirement.name)
    for package in ("scapy", "PyYAML", "matplotlib", "numpy", "Flask", "flask-sock", "waitress"):
        collect(package)
    lines = ["# Resolved runtime closure, Python 3.12. Refresh using tools/lock_dependencies.py."]
    # Click's Windows-only dependency must also be retained when locking on Linux.
    seen.setdefault("colorama", ("colorama", "0.4.6"))
    for key, (name, version) in sorted(seen.items()):
        marker = "; sys_platform == 'win32'" if key == "colorama" else ""
        requirement = f"{name}=={version}{marker}"
        if args.hashes:
            with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as response:
                release = json.load(response)
            hashes = sorted({item["digests"]["sha256"] for item in release["urls"] if not item.get("yanked")})
            if not hashes:
                raise RuntimeError(f"No non-yanked distribution hashes for {name} {version}")
            requirement += " \\\n" + " \\\n".join("    --hash=sha256:" + value for value in hashes)
        lines.append(requirement)
    (ROOT / "requirements-runtime.lock").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
