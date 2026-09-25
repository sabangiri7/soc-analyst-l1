"""
Trusted local skill packs for the AI SOC engineer.

A *skill* is a directory under ``skills/`` containing a ``SKILL.md`` file::

    ---
    name: wazuh-rule-authoring
    description: How to develop, validate, and verify Wazuh detection rules.
    version: 1.0.0
    ---
    <body - markdown instructions>

Skills are INSTRUCTIONS, not data. They are injected into the model's system
prompt inside explicit ``<SKILL name='…' role='instruction'>`` markers so the
model can always tell a skill (trusted, first-party, repo-local) apart from
retrieved Wazuh content (untrusted data). Bodies are sanitized (control chars
stripped) and marker-shaped strings are neutralized so a skill can never forge
a boundary.

Skills are trusted *only* because they live in the repo: the loader never
reads skill text from Wazuh logs, events, or the RAG store, and the CLI audits
the active skill set with every run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guard import sanitize_text

DEFAULT_SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_FRONTMATTER_RE = re.compile(r"^\ufeff?---[ \t]*\n(.*?)\n---[ \t]*\n", re.DOTALL)
_DESCRIPTION_CAP = 300


class SkillError(ValueError):
    """Raised when a skill is missing, malformed, or unsafe to load."""


def _neutralize_markers(text: str) -> str:
    """Escape marker-shaped strings inside skill bodies so a body can never
    forge an extra <SKILL> section boundary."""
    return (text.replace("</SKILL", "&lt;/SKILL")
                .replace("<SKILL", "&lt;SKILL"))


def _parse_frontmatter(raw: str) -> tuple[dict[str, Any], str]:
    """Split frontmatter (--- … ---) from the body. Raises SkillError when the
    header is absent or the required fields are missing."""
    m = _FRONTMATTER_RE.match(raw)
    if not m:
        raise SkillError("missing YAML frontmatter (--- name/description/version ---)")
    meta: dict[str, Any] = {}
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        meta[key.strip().lower()] = value.strip()
    body = raw[m.end():].strip()
    for required in ("name", "description"):
        if not meta.get(required):
            raise SkillError(f"frontmatter missing required field: {required!r}")
    return meta, body


@dataclass(frozen=True)
class Skill:
    """One loaded skill pack. `resources` lists co-located files (examples,
    snippets) shipped with the pack for the operator's reference."""

    name: str
    description: str
    version: str
    path: Path
    body: str
    resources: tuple[str, ...] = ()

    def block(self) -> str:
        """Render this skill as an instruction block for the system prompt."""
        body = _neutralize_markers(sanitize_text(self.body))
        return (
            f"\n<SKILL name='{self.name}' version='{self.version}' "
            f"role='instruction'>\n{body}\n</SKILL>\n"
        )


def _load_one(skill_dir: Path) -> Skill:
    md = skill_dir / "SKILL.md"
    try:
        raw = md.read_text(encoding="utf-8")
    except OSError as e:
        raise SkillError(f"cannot read {md}: {e}") from e
    meta, body = _parse_frontmatter(raw)
    name = str(meta["name"]).strip().lower()
    if not _NAME_RE.match(name):
        raise SkillError(
            f"skill name {name!r} is invalid (use lowercase letters, digits, hyphens)"
        )
    description = sanitize_text(str(meta["description"])).strip()[: _DESCRIPTION_CAP]
    version = str(meta.get("version") or "0.0.0").strip()
    resources = tuple(
        sorted(str(p.name) for p in skill_dir.iterdir() if p.is_file() and p.name != "SKILL.md")
    )
    return Skill(
        name=name,
        description=description,
        version=version,
        path=skill_dir,
        body=body,
        resources=resources,
    )


def discover_skills(root: str | Path | None = None) -> list[Skill]:
    """All installed skill packs, sorted by name. Malformed directories in the
    tree are skipped (never crash the whole list)."""
    base = Path(root or DEFAULT_SKILLS_ROOT)
    if not base.is_dir():
        return []
    out: list[Skill] = []
    for entry in sorted(base.iterdir()):
        if not entry.is_dir() or not (entry / "SKILL.md").exists():
            continue
        try:
            out.append(_load_one(entry))
        except SkillError:
            continue  # skip malformed packs when listing
    return out


def load_skill(name: str, root: str | Path | None = None) -> Skill:
    """Load one skill by name; raises SkillError if missing or malformed."""
    base = Path(root or DEFAULT_SKILLS_ROOT)
    skill_dir = base / str(name)
    if not skill_dir.is_dir() or not (skill_dir / "SKILL.md").exists():
        raise SkillError(f"skill {name!r} not found under {base}")
    skill = _load_one(skill_dir)
    if skill.name != name:
        raise SkillError(
            f"directory {skill_dir.name!r} declares name {skill.name!r}; "
            f"rename the directory to match"
        )
    return skill


def active_skill_blocks(names: list[str] | tuple[str, ...], root: str | Path | None = None) -> str:
    """Render the active skill set as one instruction block string for the
    system prompt. Unknown names raise SkillError (fail fast, never silently
    drop an operator's requested skill)."""
    if not names:
        return ""
    seen: set[str] = set()
    blocks: list[str] = []
    for name in names:
        name = str(name).strip().lower()
        if name in seen:
            continue
        seen.add(name)
        blocks.append(load_skill(name, root=root).block())
    return "\n".join(blocks)


def skill_names(root: str | Path | None = None) -> list[str]:
    return [s.name for s in discover_skills(root=root)]


__all__ = [
    "DEFAULT_SKILLS_ROOT",
    "Skill",
    "SkillError",
    "active_skill_blocks",
    "discover_skills",
    "load_skill",
    "skill_names",
]