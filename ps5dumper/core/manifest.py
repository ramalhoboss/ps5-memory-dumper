"""Dump manifest (manifest.json): writing, and reading old Portuguese mapas.json files."""
import json
import re
from datetime import datetime
from pathlib import Path

from .reader import NOT_ATTEMPTED

MANIFEST_NAME = "manifest.json"
LEGACY_MANIFEST_NAME = "mapas.json"
FORMAT_VERSION = 2

_LEGACY_KEYS = {
    "tipo": "type", "nota": "note", "regioes": "regions", "nome": "name", "inicio": "start",
    "fim": "end", "ficheiro": "file", "completo": "complete", "erros": "errors",
    "lacunas": "gaps", "endereco": "address", "mensagem": "message", "tamanho": "size",
    "base_dados_kernel": "kernel_data_base", "origem_base": "base_source",
    "kernel_completo": "full_kernel", "tamanho_pedido": "requested_size", "bloco": "block_size",
}
_LEGACY_TYPES = {"processo": "process", "NaoTentado": NOT_ATTEMPTED}


def save_manifest(folder, document):
    """Atomic rewrite, so a crash never leaves a half-written manifest."""
    temporary = folder / (MANIFEST_NAME + ".tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(folder / MANIFEST_NAME)


def _from_legacy(value):
    if isinstance(value, list):
        return [_from_legacy(v) for v in value]
    if not isinstance(value, dict):
        return value
    converted = {}
    for key, item in value.items():
        key = _LEGACY_KEYS.get(key, key)
        converted[key] = _LEGACY_TYPES.get(item, item) if key == "type" else _from_legacy(item)
    return converted


def find_manifest(folder):
    folder = Path(folder)
    for name in (MANIFEST_NAME, LEGACY_MANIFEST_NAME):
        if (folder / name).is_file():
            return folder / name
    return None


def load_manifest(folder):
    """Returns the manifest with English keys; version 1 (mapas.json) is converted on the fly."""
    path = find_manifest(folder)
    if path is None:
        raise FileNotFoundError(f"No {MANIFEST_NAME} or {LEGACY_MANIFEST_NAME} in {folder}")
    document = json.loads(path.read_text(encoding="utf-8"))
    if path.name == LEGACY_MANIFEST_NAME:
        document = _from_legacy(document)
        document.setdefault("format_version", 1)
        document.setdefault("gap_fill", "none")  # version 1 never padded gaps
    return document


_FOLDER_NAME = re.compile(r"^(?P<name>.*)_(?P<pid>\d+)_\d{8}_\d{6}_\d+$")


def process_name(folder, document):
    """Process name of a dump; older manifests only have it in the folder name (sanitized)."""
    if document.get("type") == "kernel":
        return "kernel"
    if document.get("process"):
        return document["process"]
    match = _FOLDER_NAME.match(Path(folder).name)
    return match["name"] if match else ""


def list_dumps(root):
    """(folder, document) for every dump under `root`, newest first; unreadable manifests get status 'unreadable'."""
    root = Path(root)
    dumps = []
    if root.is_dir():
        for folder in root.iterdir():
            if folder.is_dir() and find_manifest(folder):
                try:
                    document = load_manifest(folder)
                except (OSError, ValueError):
                    document = dict(status="unreadable", regions=[])
                dumps.append((folder, document))
    dumps.sort(key=lambda entry: started_at(*entry), reverse=True)
    return dumps


def started_at(folder, document):
    try:
        return datetime.fromisoformat(document["started"])
    except (KeyError, TypeError, ValueError):
        return datetime.fromtimestamp(Path(folder).stat().st_mtime).astimezone()


def dump_status(document):
    """Status of a manifest, including ones written before the 'status' field existed."""
    if document.get("status"):
        return document["status"]
    regions = document.get("regions", [])
    if any(r.get("errors") for r in regions):
        return "failed"
    return "complete" if regions and all(r.get("complete") for r in regions) else "incomplete"
