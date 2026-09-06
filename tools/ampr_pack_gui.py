#!/usr/bin/env python3
"""Desktop workflow for trace-derived AMPR asset packs.

The GUI intentionally calls the existing profiler and packer as subprocesses.
The binary formats and validation rules therefore stay owned by the CLI tools.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import locale
import os
from pathlib import Path, PurePosixPath
import queue
import subprocess
import sys
import threading
import tomllib
from typing import Callable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = Path(__file__).resolve().parent
PROFILE_TOOL = TOOLS_ROOT / "ampr_pack_profile.py"
PACK_TOOL = TOOLS_ROOT / "ampr_pack.py"
FROZEN = bool(getattr(sys, "frozen", False))
DISTRIBUTION_ROOT = Path(sys.executable).resolve().parent if FROZEN else REPO_ROOT

MANUAL_BEGIN = "# BEGIN AMPR PACK GUI MANUAL COVERAGE"
MANUAL_END = "# END AMPR PACK GUI MANUAL COVERAGE"
SAFETY_PATTERNS = (
    "sce_module/**",
    "system/**",
    "mods/**",
    "save/**",
    "**/*.prx",
    "**/*.sprx",
    "eboot.bin",
    "ampr_emu.index",
    "ampr_assets.index",
    "ampr_assets.index.crc",
    "ampr_assets.index.runtime",
    "ampr_assets-*.pak",
)
VALID_ACTIONS = {"compress", "store"}
VALID_LAYOUTS = {"random", "mixed", "streaming"}
VALID_BLOCK_SIZES = {"16KiB", "32KiB", "64KiB", "128KiB", "256KiB", "512KiB", "1MiB"}

SUPPORTED_LANGUAGES = {"ru", "en"}
LANGUAGE_NAMES = {"ru": "Русский", "en": "English"}
STRINGS = {
    "trace_dir_missing": {"ru": "Каталог трасс не найден: {path}", "en": "Trace directory not found: {path}"},
    "no_trace_pairs": {"ru": "В каталоге трасс не найдено ни одной пары ampr_commands.bin + ampr_emu.index", "en": "No ampr_commands.bin + ampr_emu.index pair was found in the trace directory"},
    "invalid_empty_path": {"ru": "Пустой или некорректный путь", "en": "The path is empty or invalid"},
    "path_escape": {"ru": "Путь выходит за пределы /app0: {path}", "en": "Path escapes /app0: {path}"},
    "app_root_missing": {"ru": "Исходная папка /app0 не найдена: {path}", "en": "Source /app0 directory not found: {path}"},
    "selected_outside": {"ru": "Выбранный путь должен находиться внутри исходной папки /app0", "en": "The selected path must be inside the source /app0 directory"},
    "no_whole_root": {"ru": "Добавьте нужные подпапки, а не весь корень /app0", "en": "Add the required subdirectories, not the entire /app0 root"},
    "corrupt_manual": {"ru": "В профиле повреждён блок ручного покрытия GUI", "en": "The GUI-managed manual coverage block in the profile is damaged"},
    "profile_missing": {"ru": "Профиль TOML не найден: {path}", "en": "TOML profile not found: {path}"},
    "unsupported_action": {"ru": "Неподдерживаемое действие: {value}", "en": "Unsupported action: {value}"},
    "unsupported_layout": {"ru": "Неподдерживаемая схема доступа: {value}", "en": "Unsupported access layout: {value}"},
    "unsupported_block": {"ru": "Неподдерживаемый размер блока: {value}", "en": "Unsupported block size: {value}"},
    "invalid_profile_after": {"ru": "После добавления правил профиль TOML некорректен: {error}", "en": "The TOML profile is invalid after adding the rules: {error}"},
    "unsafe_index": {"ru": "Небезопасный pack.index_name в профиле", "en": "Unsafe pack.index_name in the profile"},
    "tk_unavailable": {"ru": "Tkinter недоступен. Установите компонент Python Tcl/Tk.", "en": "Tkinter is unavailable. Install the Python Tcl/Tk component."},
    "title": {"ru": "AMPR — сборка паков ассетов", "en": "AMPR — Asset Pack Builder"},
    "ready": {"ru": "Готово", "en": "Ready"},
    "language": {"ru": "Язык / Language:", "en": "Language / Язык:"},
    "trace_warning": {"ru": "ВАЖНО: трассы содержат только фактически увиденные APR-чтения. Они не описывают всю игру. Перед сборкой дополните профиль оставшимися файлами и папками реальной игры.", "en": "IMPORTANT: traces contain only APR reads that were actually observed. They do not describe the entire game. Before packing, add the remaining files and directories from the real game to the profile."},
    "paths_group": {"ru": "1. Исходные данные и результат", "en": "1. Inputs and output"},
    "trace_folder": {"ru": "Папка с трассами", "en": "Trace directory"},
    "app_copy": {"ru": "Полная копия /app0", "en": "Complete /app0 copy"},
    "ampr_index": {"ru": "Индекс ampr_emu.index", "en": "ampr_emu.index file"},
    "toml_profile": {"ru": "Профиль TOML", "en": "TOML profile"},
    "pack_output": {"ru": "Папка готовых паков", "en": "Pack output directory"},
    "browse": {"ru": "Обзор…", "en": "Browse…"},
    "manual_group": {"ru": "2. Все пути, выбранные для упаковки", "en": "2. All paths selected for packing"},
    "manual_help": {"ru": "Нажмите «Загрузить из профиля», чтобы увидеть трассовые и ручные пути вместе. Добавляйте недостающие данные; удаление трассового пути сохранит для него loose-исключение. Режим, доступ и блок применяются только к новым ручным путям.", "en": "Click Load from profile to see trace-derived and manual paths together. Add missing data; removing a trace-derived path saves a loose override for it. Mode, access, and block apply only to new manual paths."},
    "add_files": {"ru": "Добавить файлы…", "en": "Add files…"},
    "add_folder": {"ru": "Добавить папку…", "en": "Add directory…"},
    "add_pattern": {"ru": "Добавить маску…", "en": "Add pattern…"},
    "remove_selected": {"ru": "Удалить выбранное", "en": "Remove selected"},
    "load_profile": {"ru": "Загрузить из профиля", "en": "Load from profile"},
    "mode": {"ru": "Режим:", "en": "Mode:"},
    "access": {"ru": "Доступ:", "en": "Access:"},
    "block": {"ru": "Блок:", "en": "Block:"},
    "coverage_consent": {"ru": "Я проверил содержимое реальной игры и понимаю, что трассы неполны; необходимые оставшиеся пути добавлены или сознательно оставлены loose.", "en": "I reviewed the real game contents and understand that traces are incomplete; required remaining paths were added or intentionally left loose."},
    "generate_profile": {"ru": "1. Создать профиль из трасс", "en": "1. Generate profile from traces"},
    "save_manual": {"ru": "2. Сохранить изменения путей", "en": "2. Save path changes"},
    "pack_verify": {"ru": "3. Собрать и проверить", "en": "3. Pack and verify"},
    "verify_ready": {"ru": "Проверить готовые паки", "en": "Verify existing packs"},
    "inspect": {"ru": "Показать сводку", "en": "Show summary"},
    "cancel": {"ru": "Остановить", "en": "Stop"},
    "remove_empty": {"ru": "Удалить также опустевшие каталоги", "en": "Also remove directories that become empty"},
    "remove_packed": {"ru": "Удалить из /app0 файлы со статусом PACK…", "en": "Remove PACK files from /app0…"},
    "progress": {"ru": "Ход выполнения", "en": "Progress"},
    "all_files": {"ru": "Все файлы", "en": "All files"},
    "invalid_path": {"ru": "Некорректный путь", "en": "Invalid path"},
    "pattern_title": {"ru": "Маска /app0", "en": "/app0 pattern"},
    "pattern_prompt": {"ru": "Введите путь или маску относительно /app0, например dlc/**:", "en": "Enter a path or pattern relative to /app0, for example dlc/**:"},
    "invalid_pattern": {"ru": "Некорректная маска", "en": "Invalid pattern"},
    "loaded_paths": {"ru": "Загружено ручных путей: {count}", "en": "Manual paths loaded: {count}"},
    "loaded_all_paths": {"ru": "Загружено путей: {count} (из трассовых правил: {profile}, ручных: {manual})", "en": "Paths loaded: {count} (trace-profile rules: {profile}, manual: {manual})"},
    "no_manual_title": {"ru": "Ручные пути не найдены", "en": "No manual paths found"},
    "no_manual_paths": {"ru": "В выбранном профиле ещё нет сохранённого GUI-правила с ручными путями.", "en": "The selected profile does not contain a saved GUI-managed manual-path rule yet."},
    "no_profile_paths": {"ru": "В выбранном профиле нет путей со статусом compress/store.", "en": "The selected profile contains no paths with compress/store status."},
    "profile_changed": {"ru": "После загрузки списка был выбран другой TOML. Сначала нажмите «Загрузить из профиля», чтобы не перенести пути между профилями.", "en": "A different TOML was selected after loading the list. Click Load from profile first to avoid copying paths between profiles."},
    "load_failed": {"ru": "Не удалось загрузить пути", "en": "Could not load paths"},
    "invalid_manual_block": {"ru": "В профиле некорректно оформлен блок ручного покрытия GUI", "en": "The GUI-managed manual coverage block in the profile is invalid"},
    "invalid_profile": {"ru": "Выбранный профиль TOML некорректен: {error}", "en": "The selected TOML profile is invalid: {error}"},
    "manual_list_invalid": {"ru": "Поле {field} ручного правила должно быть списком строк", "en": "Manual-rule field {field} must be a list of strings"},
    "manual_list_absolute": {"ru": "Путь {path} в include_from должен быть относительным к TOML", "en": "include_from path {path} must be relative to the TOML file"},
    "manual_list_escape": {"ru": "Путь {path} в include_from выходит за каталог TOML", "en": "include_from path {path} escapes the TOML directory"},
    "manual_list_missing": {"ru": "Файл ручных путей не найден: {path}", "en": "Manual-path file not found: {path}"},
    "profile_updated": {"ru": "Профиль обновлён", "en": "Profile updated"},
    "manual_saved": {"ru": "Изменения путей сохранены в профиле:\n{path}", "en": "Path changes saved in the profile:\n{path}"},
    "profile_update_failed": {"ru": "Не удалось обновить профиль", "en": "Could not update profile"},
    "index_missing": {"ru": "Индекс ampr_emu.index не найден: {path}", "en": "ampr_emu.index not found: {path}"},
    "source_missing": {"ru": "Не хватает исходных данных", "en": "Required inputs are missing"},
    "profile_created": {"ru": "Профиль создан. Теперь проверьте и дополните ручное покрытие.", "en": "Profile generated. Now review and complete its manual coverage."},
    "profile_generation": {"ru": "Генерация профиля", "en": "Profile generation"},
    "coverage_required": {"ru": "Нужно проверить покрытие", "en": "Coverage review required"},
    "coverage_pack_prompt": {"ru": "Сначала подтвердите, что профиль адаптирован под реальную игру, а непокрытые пути сознательно оставлены loose.", "en": "First confirm that the profile was adapted to the real game and that uncovered paths were intentionally left loose."},
    "pack_start_failed": {"ru": "Не удалось начать сборку", "en": "Could not start packing"},
    "packing": {"ru": "Сборка паков", "en": "Building packs"},
    "full_verify": {"ru": "Полная проверка CRC и сравнение с оригиналами", "en": "Full CRC verification and source comparison"},
    "manifest_summary": {"ru": "Сводка манифеста", "en": "Manifest summary"},
    "verified": {"ru": "Готово и проверено: {path}", "en": "Built and verified: {path}"},
    "verify_start_failed": {"ru": "Не удалось начать проверку", "en": "Could not start verification"},
    "verify_packs": {"ru": "Проверка паков", "en": "Pack verification"},
    "inspect_failed": {"ru": "Не удалось прочитать сводку", "en": "Could not read the summary"},
    "coverage_remove_prompt": {"ru": "Удаление доступно только после подтверждения ручной проверки покрытия игры.", "en": "Removal is available only after confirming the manual game coverage review."},
    "remove_prepare_failed": {"ru": "Нельзя подготовить удаление", "en": "Could not prepare removal"},
    "nothing_to_remove": {"ru": "Удалять нечего", "en": "Nothing to remove"},
    "no_pack_sources": {"ru": "В выбранной /app0 нет исходных PACK-файлов.", "en": "The selected /app0 contains no source files marked PACK."},
    "permanent_removal": {"ru": "Безвозвратное удаление", "en": "Permanent removal"},
    "removal_confirm": {"ru": "Будут безвозвратно удалены {files} файлов ({size:.1f} MiB) из:\n{root}\n\nПеред удалением программа заново проверит паки и побайтово сравнит их с оригиналами. Verify не доказывает полноту игровых трасс или поддержку mmap. Убедитесь, что у вас есть резервная копия.\n\nПродолжить?", "en": "This will permanently remove {files} files ({size:.1f} MiB) from:\n{root}\n\nBefore removal, the program will verify the packs again and compare them byte-for-byte with the originals. Verify does not prove complete gameplay trace coverage or mmap support. Make sure you have a backup.\n\nContinue?"},
    "remove_sources": {"ru": "Проверка и удаление исходных PACK-файлов", "en": "Verifying and removing source PACK files"},
    "sources_removed": {"ru": "PACK-файлы удалены из {path}", "en": "PACK source files removed from {path}"},
    "already_running": {"ru": "Операция уже выполняется", "en": "An operation is already running"},
    "wait_or_stop": {"ru": "Дождитесь завершения или нажмите «Остановить».", "en": "Wait for completion or click Stop."},
    "running": {"ru": "Выполняется…", "en": "Running…"},
    "operation_stopped": {"ru": "Операция остановлена", "en": "Operation stopped"},
    "exit_code": {"ru": "{title}: код завершения {code}", "en": "{title}: exit code {code}"},
    "operation_success": {"ru": "Операция завершена успешно", "en": "Operation completed successfully"},
    "stopping": {"ru": "Остановка…", "en": "Stopping…"},
    "operation_failed": {"ru": "Операция не выполнена", "en": "Operation failed"},
}


def detect_system_language() -> str:
    """Choose Russian for Russian locales and English for every other locale."""
    current = None
    try:
        current = locale.getlocale()[0]
    except (TypeError, ValueError):
        pass
    if not current:
        current = next(
            filter(None, (os.environ.get("LC_ALL"), os.environ.get("LC_MESSAGES"), os.environ.get("LANG"))),
            "",
        )
    normalized = current.lower().replace("-", "_")
    return "ru" if normalized.startswith(("ru", "russian")) else "en"


ACTIVE_LANGUAGE = detect_system_language()


def set_language(language: str) -> None:
    """Set the language used by GUI labels and user-facing validation errors."""
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"unsupported language: {language}")
    global ACTIVE_LANGUAGE
    ACTIVE_LANGUAGE = language


def tr(key: str, **values: object) -> str:
    """Return one localized string."""
    return STRINGS[key][ACTIVE_LANGUAGE].format(**values)


class GuiInputError(ValueError):
    """A user-facing validation error."""


@dataclass(frozen=True)
class ManualCoverage:
    """GUI-managed paths and the options stored with their TOML rule."""

    patterns: tuple[str, ...]
    excluded_patterns: tuple[str, ...] = ()
    action: str = "compress"
    layout: str = "mixed"
    block_size: str = "64KiB"
    saved: bool = False


@dataclass(frozen=True)
class ProfileCoverage:
    """Editable effective pack selection without flattening generated rules."""

    base_patterns: tuple[str, ...]
    manual: ManualCoverage

    @property
    def effective_patterns(self) -> tuple[str, ...]:
        effective = (set(self.base_patterns) - set(self.manual.excluded_patterns)) | set(self.manual.patterns)
        return tuple(sorted(effective, key=str.casefold))


def discover_trace_pairs(root: Path) -> list[tuple[Path, Path]]:
    """Return journal/index pairs below *root* in stable order."""
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise GuiInputError(tr("trace_dir_missing", path=root))
    pairs = []
    for commands in sorted(root.rglob("ampr_commands.bin")):
        index = commands.with_name("ampr_emu.index")
        if index.is_file():
            pairs.append((commands, index))
    if not pairs:
        raise GuiInputError(tr("no_trace_pairs"))
    return pairs


def normalize_manual_pattern(value: str) -> str:
    """Normalize one /app0-relative file or glob pattern."""
    pattern = value.strip().replace("\\", "/")
    if pattern.lower().startswith("/app0/"):
        pattern = pattern[6:]
    pattern = pattern.lstrip("/")
    if not pattern or "\0" in pattern or "\n" in pattern or "\r" in pattern:
        raise GuiInputError(tr("invalid_empty_path"))
    parts = PurePosixPath(pattern).parts
    if any(part in ("", ".", "..") for part in parts):
        raise GuiInputError(tr("path_escape", path=value))
    return PurePosixPath(*parts).as_posix()


def selected_path_to_pattern(app_root: Path, selected: Path, *, directory: bool) -> str:
    """Convert a selected host path to a safe /app0-relative pack pattern."""
    root = app_root.expanduser().resolve()
    candidate = selected.expanduser().resolve()
    if not root.is_dir():
        raise GuiInputError(tr("app_root_missing", path=root))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise GuiInputError(tr("selected_outside")) from exc
    if not relative.parts:
        raise GuiInputError(tr("no_whole_root"))
    pattern = relative.as_posix()
    if directory:
        pattern += "/**"
    return normalize_manual_pattern(pattern)


def manual_sidecar_path(profile_path: Path) -> Path:
    return profile_path.with_name(f"{profile_path.stem}.manual.include.txt")


def manual_exclude_sidecar_path(profile_path: Path) -> Path:
    return profile_path.with_name(f"{profile_path.stem}.manual.exclude.txt")


def _manual_block(text: str) -> str | None:
    start = text.find(MANUAL_BEGIN)
    end = text.find(MANUAL_END)
    if start < 0 and end < 0:
        return None
    if start < 0 or end < start:
        raise GuiInputError(tr("corrupt_manual"))
    return text[start + len(MANUAL_BEGIN) : end]


def _manual_string_list(value: object, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise GuiInputError(tr("manual_list_invalid", field=field))
    return value


def _read_pattern_file(path: Path) -> list[str]:
    if not path.is_file():
        raise GuiInputError(tr("manual_list_missing", path=path))
    result = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            result.append(normalize_manual_pattern(line))
    return result


def _rule_patterns(rule: dict[str, object], config_root: Path) -> list[str]:
    patterns = [
        normalize_manual_pattern(value)
        for value in _manual_string_list(rule.get("include"), "include")
    ]
    for name in _manual_string_list(rule.get("include_from"), "include_from"):
        relative = Path(name)
        if relative.is_absolute():
            raise GuiInputError(tr("manual_list_absolute", path=name))
        candidate = (config_root / relative).resolve()
        try:
            inside = os.path.commonpath((str(config_root), str(candidate))) == str(config_root)
        except ValueError:
            inside = False
        if not inside:
            raise GuiInputError(tr("manual_list_escape", path=name))
        patterns.extend(_read_pattern_file(candidate))
    return patterns


def load_manual_coverage(profile_path: Path) -> ManualCoverage:
    """Load only the GUI-managed rule associated with the selected TOML."""
    profile_path = profile_path.expanduser().resolve()
    if not profile_path.is_file():
        raise GuiInputError(tr("profile_missing", path=profile_path))
    block = _manual_block(profile_path.read_text(encoding="utf-8"))
    if block is None:
        # Compatibility with early GUI profiles that only had the conventional
        # sidecar. Never import profiler-generated rules as manual coverage.
        sidecar = manual_sidecar_path(profile_path)
        if not sidecar.is_file():
            return ManualCoverage(patterns=())
        return ManualCoverage(
            patterns=tuple(sorted(set(_read_pattern_file(sidecar)), key=str.casefold)),
            saved=True,
        )

    try:
        parsed = tomllib.loads(block)
    except tomllib.TOMLDecodeError as exc:
        raise GuiInputError(f"{tr('invalid_manual_block')}: {exc}") from exc
    rules = parsed.get("rule")
    if not isinstance(rules, list) or not rules or any(not isinstance(rule, dict) for rule in rules):
        raise GuiInputError(tr("invalid_manual_block"))
    config_root = profile_path.parent.resolve()
    patterns: list[str] = []
    excluded_patterns: list[str] = []
    action = "compress"
    layout = "mixed"
    block_size = "64KiB"
    found_addition_rule = False
    for rule in rules:
        rule_action = str(rule.get("action", "compress"))
        rule_patterns = _rule_patterns(rule, config_root)
        if rule.get("force_pack") is True and rule_action in VALID_ACTIONS:
            if not found_addition_rule:
                action = rule_action
                layout = str(rule.get("layout", "mixed"))
                block_size = str(rule.get("block_size", "64KiB"))
                found_addition_rule = True
            patterns.extend(rule_patterns)
        elif rule_action == "loose" and not set(SAFETY_PATTERNS).issubset(rule_patterns):
            excluded_patterns.extend(rule_patterns)
    if found_addition_rule:
        if layout not in VALID_LAYOUTS:
            raise GuiInputError(tr("unsupported_layout", value=layout))
        if block_size not in VALID_BLOCK_SIZES:
            raise GuiInputError(tr("unsupported_block", value=block_size))
    if not found_addition_rule and not excluded_patterns:
        raise GuiInputError(tr("invalid_manual_block"))
    return ManualCoverage(
        patterns=tuple(sorted(set(patterns), key=str.casefold)),
        excluded_patterns=tuple(sorted(set(excluded_patterns), key=str.casefold)),
        action=action,
        layout=layout,
        block_size=block_size,
        saved=True,
    )


def load_manual_patterns(profile_path: Path) -> list[str]:
    """Compatibility helper returning paths from the GUI-managed TOML rule."""
    return list(load_manual_coverage(profile_path).patterns)


def load_profile_coverage(profile_path: Path) -> ProfileCoverage:
    """Load all packed include paths while keeping GUI edits separate."""
    profile_path = profile_path.expanduser().resolve()
    if not profile_path.is_file():
        raise GuiInputError(tr("profile_missing", path=profile_path))
    text = profile_path.read_text(encoding="utf-8")
    try:
        parsed = tomllib.loads(_without_manual_block(text))
    except tomllib.TOMLDecodeError as exc:
        raise GuiInputError(tr("invalid_profile", error=exc)) from exc
    rules = parsed.get("rule", [])
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        raise GuiInputError(tr("invalid_profile", error="[[rule]] must be an array of tables"))
    config_root = profile_path.parent.resolve()
    base_patterns: list[str] = []
    for rule in rules:
        if str(rule.get("action", "compress")) in VALID_ACTIONS:
            base_patterns.extend(_rule_patterns(rule, config_root))
    return ProfileCoverage(
        base_patterns=tuple(sorted(set(base_patterns), key=str.casefold)),
        manual=load_manual_coverage(profile_path),
    )


def _without_manual_block(text: str) -> str:
    block = _manual_block(text)
    if block is None:
        return text.rstrip() + "\n"
    start = text.find(MANUAL_BEGIN)
    end = text.find(MANUAL_END)
    end += len(MANUAL_END)
    return (text[:start].rstrip() + "\n" + text[end:].lstrip()).rstrip() + "\n"


def apply_manual_coverage(
    profile_path: Path,
    patterns: Sequence[str],
    *,
    excluded_patterns: Sequence[str] = (),
    action: str = "compress",
    layout: str = "mixed",
    block_size: str = "64KiB",
) -> Path:
    """Append/replace the GUI-managed rule and keep safety exclusions last."""
    profile_path = profile_path.expanduser().resolve()
    if not profile_path.is_file():
        raise GuiInputError(tr("profile_missing", path=profile_path))
    if action not in VALID_ACTIONS:
        raise GuiInputError(tr("unsupported_action", value=action))
    if layout not in VALID_LAYOUTS:
        raise GuiInputError(tr("unsupported_layout", value=layout))
    if block_size not in VALID_BLOCK_SIZES:
        raise GuiInputError(tr("unsupported_block", value=block_size))

    normalized = sorted(
        {normalize_manual_pattern(pattern) for pattern in patterns}, key=str.casefold
    )
    normalized_excluded = sorted(
        {normalize_manual_pattern(pattern) for pattern in excluded_patterns}, key=str.casefold
    )
    original = profile_path.read_text(encoding="utf-8")
    base = _without_manual_block(original)
    sidecar = manual_sidecar_path(profile_path)
    exclude_sidecar = manual_exclude_sidecar_path(profile_path)

    if normalized or normalized_excluded:
        relative_sidecar = sidecar.name
        lines = [MANUAL_BEGIN]
        if normalized:
            lines.extend([
                "# Added by the user after reviewing files/directories not covered by traces.",
                "[[rule]]",
                f"action = {json.dumps(action)}",
                f"include_from = [{json.dumps(relative_sidecar, ensure_ascii=False)}]",
                f"block_size = {json.dumps(block_size)}",
                f"layout = {json.dumps(layout)}",
                "force_pack = true",
                "",
            ])
        if normalized_excluded:
            lines.extend([
                "# Removed by the user from the trace-generated packed selection.",
                "[[rule]]",
                'action = "loose"',
                f"include_from = [{json.dumps(exclude_sidecar.name, ensure_ascii=False)}]",
                "",
            ])
        lines.extend([
            "# Repeat hard safety exclusions: rules use last-match-wins semantics.",
            "[[rule]]",
            'action = "loose"',
            "include = [",
        ])
        lines.extend(f"  {json.dumps(pattern)}," for pattern in SAFETY_PATTERNS)
        lines.extend(["]", MANUAL_END, ""])
        updated = base.rstrip() + "\n\n" + "\n".join(lines)
    else:
        updated = base

    try:
        tomllib.loads(updated)
    except tomllib.TOMLDecodeError as exc:
        raise GuiInputError(tr("invalid_profile_after", error=exc)) from exc

    profile_path.parent.mkdir(parents=True, exist_ok=True)
    sidecar_temp = sidecar.with_name(f".{sidecar.name}.tmp-{os.getpid()}")
    exclude_temp = exclude_sidecar.with_name(f".{exclude_sidecar.name}.tmp-{os.getpid()}")
    profile_temp = profile_path.with_name(f".{profile_path.name}.tmp-{os.getpid()}")
    sidecar_temp.write_text("".join(f"{pattern}\n" for pattern in normalized), encoding="utf-8", newline="\n")
    exclude_temp.write_text("".join(f"{pattern}\n" for pattern in normalized_excluded), encoding="utf-8", newline="\n")
    profile_temp.write_text(updated, encoding="utf-8", newline="\n")
    os.replace(sidecar_temp, sidecar)
    os.replace(exclude_temp, exclude_sidecar)
    os.replace(profile_temp, profile_path)
    return sidecar


def manifest_path(output_dir: Path, profile_path: Path) -> Path:
    """Resolve the manifest name selected by the TOML profile."""
    name = "ampr_assets.index"
    if profile_path.is_file():
        with profile_path.open("rb") as handle:
            parsed = tomllib.load(handle)
        pack = parsed.get("pack", {})
        if isinstance(pack, dict):
            candidate = str(pack.get("index_name", name))
            if Path(candidate).is_absolute() or ".." in PurePosixPath(candidate.replace("\\", "/")).parts:
                raise GuiInputError(tr("unsafe_index"))
            name = candidate
    return output_dir.expanduser().resolve() / Path(name)


def build_profile_command(trace_root: Path, profile: Path) -> list[str]:
    pairs = discover_trace_pairs(trace_root)
    report = profile.with_suffix(".report.md")
    metrics = profile.with_suffix(".metrics.json")
    command = tool_command("profile", "generate")
    for commands, index in pairs:
        command.extend(("--trace", str(commands), str(index)))
    command.extend(
        (
            "--output", str(profile),
            "--report", str(report),
            "--metrics", str(metrics),
            "--pattern-mode", "exact",
            "--cache-sim",
            "--cache-max-touches", "250000",
            "--overwrite",
        )
    )
    return command


def tool_command(tool: str, *arguments: str) -> list[str]:
    """Build a source-tree or frozen self-dispatch command."""
    if tool not in {"pack", "profile"}:
        raise ValueError(f"unknown bundled tool: {tool}")
    if FROZEN:
        return [sys.executable, f"--internal-{tool}", *arguments]
    script = PACK_TOOL if tool == "pack" else PROFILE_TOOL
    return [sys.executable, str(script), *arguments]


def run_gui(language: str | None = None) -> int:
    if language is not None:
        set_language(language)
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, simpledialog, ttk
        from tkinter.scrolledtext import ScrolledText
    except ImportError:
        print(tr("tk_unavailable"), file=sys.stderr)
        return 2

    if FROZEN and sys.platform == "win32":
        # The executable is built as a console application so child CLI modes
        # retain stdout/stderr pipes. Hide that console only in interactive GUI
        # mode; internal pack/profile subprocesses never reach this branch.
        try:
            import ctypes

            console = ctypes.windll.kernel32.GetConsoleWindow()
            if console:
                ctypes.windll.user32.ShowWindow(console, 0)
        except (AttributeError, OSError):
            pass

    class AssetPackApp(tk.Tk):
        def __init__(self) -> None:
            super().__init__()
            self.title(tr("title"))
            self.geometry("1040x760")
            self.minsize(900, 650)
            self.events: queue.Queue[tuple[object, ...]] = queue.Queue()
            self.process: subprocess.Popen[str] | None = None
            self.worker: threading.Thread | None = None
            self.cancel_requested = threading.Event()
            self.action_buttons: list[ttk.Button] = []
            self.outer = None
            self.loaded_profile_path: Path | None = None
            self.base_profile_patterns: set[str] = set()

            case_root = (
                DISTRIBUTION_ROOT / "work" / "title"
                if FROZEN
                else REPO_ROOT / "profiling" / "title"
            )
            self.trace_root = tk.StringVar(value=str(case_root / "traces"))
            self.app_root = tk.StringVar(value=str(case_root / "app0"))
            self.ampr_index = tk.StringVar(value=str(case_root / "app0" / "ampr_emu.index"))
            self.profile = tk.StringVar(value=str(case_root / "profiles" / "title.toml"))
            self.output = tk.StringVar(value=str(case_root / "packed"))
            self.manual_action = tk.StringVar(value="compress")
            self.manual_layout = tk.StringVar(value="mixed")
            self.manual_block = tk.StringVar(value="64KiB")
            self.reviewed = tk.BooleanVar(value=False)
            self.remove_empty_dirs = tk.BooleanVar(value=True)
            self.status = tk.StringVar(value=tr("ready"))
            self.language_name = tk.StringVar(value=LANGUAGE_NAMES[ACTIVE_LANGUAGE])

            self._build_ui(ttk, filedialog, messagebox, simpledialog, ScrolledText)
            self.protocol("WM_DELETE_WINDOW", self._close)
            self.after(100, self._poll_events)

        def _build_ui(self, ttk, filedialog, messagebox, simpledialog, ScrolledText) -> None:
            patterns = self._pattern_values() if hasattr(self, "patterns") else []
            log_text = self.log.get("1.0", "end-1c") if hasattr(self, "log") else ""
            if self.outer is not None:
                self.outer.destroy()
            self.action_buttons.clear()
            self.title(tr("title"))
            outer = ttk.Frame(self, padding=12)
            outer.pack(fill="both", expand=True)
            self.outer = outer

            language_row = ttk.Frame(outer)
            language_row.pack(fill="x", pady=(0, 6))
            ttk.Label(language_row, text=tr("language")).pack(side="right", padx=(6, 0))
            self.language_combo = ttk.Combobox(
                language_row,
                textvariable=self.language_name,
                values=(LANGUAGE_NAMES["ru"], LANGUAGE_NAMES["en"]),
                state="readonly",
                width=10,
            )
            self.language_combo.pack(side="right")
            self.language_combo.bind(
                "<<ComboboxSelected>>",
                lambda _event: self._change_language(ttk, filedialog, messagebox, simpledialog, ScrolledText),
            )

            warning = tk.Label(
                outer,
                text=tr("trace_warning"),
                bg="#7a3e00",
                fg="white",
                padx=12,
                pady=10,
                justify="left",
                wraplength=980,
            )
            warning.pack(fill="x", pady=(0, 10))

            paths = ttk.LabelFrame(outer, text=tr("paths_group"), padding=10)
            paths.pack(fill="x")
            rows = (
                (tr("trace_folder"), self.trace_root, True, "dir"),
                (tr("app_copy"), self.app_root, True, "dir"),
                (tr("ampr_index"), self.ampr_index, True, "file"),
                (tr("toml_profile"), self.profile, False, "save"),
                (tr("pack_output"), self.output, False, "dir"),
            )
            for row, (label, variable, must_exist, kind) in enumerate(rows):
                ttk.Label(paths, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=3)
                ttk.Entry(paths, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=3)
                ttk.Button(
                    paths,
                    text=tr("browse"),
                    command=lambda v=variable, k=kind, e=must_exist: self._browse(v, k, e, filedialog),
                ).grid(row=row, column=2, padx=(8, 0), pady=3)
            paths.columnconfigure(1, weight=1)

            manual = ttk.LabelFrame(outer, text=tr("manual_group"), padding=10)
            manual.pack(fill="both", expand=False, pady=10)
            ttk.Label(
                manual,
                text=tr("manual_help"),
                wraplength=960,
                justify="left",
            ).grid(row=0, column=0, columnspan=5, sticky="w", pady=(0, 6))
            self.patterns = tk.Listbox(manual, height=7, selectmode="extended")
            self.patterns.grid(row=1, column=0, columnspan=4, sticky="nsew")
            scrollbar = ttk.Scrollbar(manual, orient="vertical", command=self.patterns.yview)
            scrollbar.grid(row=1, column=4, sticky="ns")
            self.patterns.configure(yscrollcommand=scrollbar.set)
            self._insert_patterns(patterns)

            buttons = ttk.Frame(manual)
            buttons.grid(row=2, column=0, columnspan=5, sticky="w", pady=(6, 4))
            ttk.Button(buttons, text=tr("add_files"), command=lambda: self._add_files(filedialog, messagebox)).pack(side="left")
            ttk.Button(buttons, text=tr("add_folder"), command=lambda: self._add_folder(filedialog, messagebox)).pack(side="left", padx=5)
            ttk.Button(buttons, text=tr("add_pattern"), command=lambda: self._add_pattern(simpledialog, messagebox)).pack(side="left")
            ttk.Button(buttons, text=tr("remove_selected"), command=self._remove_patterns).pack(side="left", padx=5)
            ttk.Button(buttons, text=tr("load_profile"), command=lambda: self._load_manual(messagebox)).pack(side="left")

            options = ttk.Frame(manual)
            options.grid(row=3, column=0, columnspan=5, sticky="w", pady=(3, 0))
            ttk.Label(options, text=tr("mode")).pack(side="left")
            ttk.Combobox(options, textvariable=self.manual_action, values=("compress", "store"), state="readonly", width=10).pack(side="left", padx=(4, 12))
            ttk.Label(options, text=tr("access")).pack(side="left")
            ttk.Combobox(options, textvariable=self.manual_layout, values=("mixed", "random", "streaming"), state="readonly", width=10).pack(side="left", padx=(4, 12))
            ttk.Label(options, text=tr("block")).pack(side="left")
            ttk.Combobox(options, textvariable=self.manual_block, values=tuple(sorted(VALID_BLOCK_SIZES)), state="readonly", width=9).pack(side="left", padx=4)
            manual.columnconfigure(3, weight=1)

            consent = ttk.Checkbutton(
                outer,
                variable=self.reviewed,
                text=tr("coverage_consent"),
            )
            consent.pack(fill="x", pady=(0, 8))

            actions = ttk.Frame(outer)
            actions.pack(fill="x")
            for text, command in (
                (tr("generate_profile"), lambda: self._generate(messagebox)),
                (tr("save_manual"), lambda: self._save_manual(messagebox, notify=True)),
                (tr("pack_verify"), lambda: self._pack_and_verify(messagebox)),
                (tr("verify_ready"), lambda: self._verify(messagebox)),
                (tr("inspect"), lambda: self._inspect(messagebox)),
            ):
                button = ttk.Button(actions, text=text, command=command)
                button.pack(side="left", padx=(0, 6))
                self.action_buttons.append(button)
            self.cancel_button = ttk.Button(actions, text=tr("cancel"), command=self._cancel, state="disabled")
            self.cancel_button.pack(side="right")

            cleanup = ttk.Frame(outer)
            cleanup.pack(fill="x", pady=(8, 0))
            ttk.Checkbutton(
                cleanup,
                variable=self.remove_empty_dirs,
                text=tr("remove_empty"),
            ).pack(side="left")
            remove_button = ttk.Button(
                cleanup,
                text=tr("remove_packed"),
                command=lambda: self._remove_packed_sources(messagebox),
            )
            remove_button.pack(side="right")
            self.action_buttons.append(remove_button)

            log_frame = ttk.LabelFrame(outer, text=tr("progress"), padding=6)
            log_frame.pack(fill="both", expand=True, pady=(10, 0))
            self.log = ScrolledText(log_frame, height=12, wrap="word", state="disabled", font=("Consolas", 9))
            self.log.pack(fill="both", expand=True)
            if log_text:
                self._append_log(log_text)
            ttk.Label(outer, textvariable=self.status).pack(fill="x", pady=(5, 0))

        def _change_language(self, ttk, filedialog, messagebox, simpledialog, ScrolledText) -> None:
            selected = self.language_name.get()
            language = next(code for code, name in LANGUAGE_NAMES.items() if name == selected)
            set_language(language)
            self.status.set(tr("ready"))
            self._build_ui(ttk, filedialog, messagebox, simpledialog, ScrolledText)

        def _browse(self, variable, kind: str, must_exist: bool, filedialog) -> None:
            current = Path(variable.get()).expanduser()
            initial = current if current.is_dir() else current.parent
            if kind == "file":
                result = filedialog.askopenfilename(initialdir=initial, filetypes=(("AMPR index", "*.index"), (tr("all_files"), "*.*")))
            elif kind == "save":
                result = filedialog.asksaveasfilename(initialdir=initial, initialfile=current.name, defaultextension=".toml", filetypes=(("TOML", "*.toml"),))
            else:
                result = filedialog.askdirectory(initialdir=initial, mustexist=must_exist)
            if result:
                variable.set(result)
                if variable is self.app_root:
                    self.ampr_index.set(str(Path(result) / "ampr_emu.index"))

        def _pattern_values(self) -> list[str]:
            return [self.patterns.get(index) for index in range(self.patterns.size())]

        def _insert_patterns(self, values: Sequence[str]) -> None:
            existing = set(self._pattern_values())
            for value in values:
                if value not in existing:
                    self.patterns.insert("end", value)
                    existing.add(value)

        def _add_files(self, filedialog, messagebox) -> None:
            try:
                root = Path(self.app_root.get())
                selected = filedialog.askopenfilenames(initialdir=root)
                self._insert_patterns([selected_path_to_pattern(root, Path(path), directory=False) for path in selected])
            except (GuiInputError, OSError) as exc:
                messagebox.showerror(tr("invalid_path"), str(exc))

        def _add_folder(self, filedialog, messagebox) -> None:
            try:
                root = Path(self.app_root.get())
                selected = filedialog.askdirectory(initialdir=root, mustexist=True)
                if selected:
                    self._insert_patterns([selected_path_to_pattern(root, Path(selected), directory=True)])
            except (GuiInputError, OSError) as exc:
                messagebox.showerror(tr("invalid_path"), str(exc))

        def _add_pattern(self, simpledialog, messagebox) -> None:
            value = simpledialog.askstring(tr("pattern_title"), tr("pattern_prompt"))
            if value:
                try:
                    self._insert_patterns([normalize_manual_pattern(value)])
                except GuiInputError as exc:
                    messagebox.showerror(tr("invalid_pattern"), str(exc))

        def _remove_patterns(self) -> None:
            for index in reversed(self.patterns.curselection()):
                self.patterns.delete(index)

        def _load_manual(self, messagebox) -> None:
            try:
                profile = Path(self.profile.get()).expanduser().resolve()
                coverage = load_profile_coverage(profile)
                if not coverage.base_patterns and not coverage.manual.patterns:
                    messagebox.showinfo(tr("no_manual_title"), tr("no_profile_paths"))
                self.patterns.delete(0, "end")
                self._insert_patterns(coverage.effective_patterns)
                self.loaded_profile_path = profile
                self.base_profile_patterns = set(coverage.base_patterns)
                self.manual_action.set(coverage.manual.action)
                self.manual_layout.set(coverage.manual.layout)
                self.manual_block.set(coverage.manual.block_size)
                self.status.set(tr(
                    "loaded_all_paths",
                    count=len(coverage.effective_patterns),
                    profile=len(coverage.base_patterns),
                    manual=len(coverage.manual.patterns),
                ))
            except (GuiInputError, OSError) as exc:
                messagebox.showerror(tr("load_failed"), str(exc))

        def _save_manual(self, messagebox, *, notify: bool) -> bool:
            try:
                profile = Path(self.profile.get()).expanduser().resolve()
                current = set(self._pattern_values())
                if self.loaded_profile_path is not None and self.loaded_profile_path != profile:
                    raise GuiInputError(tr("profile_changed"))
                if self.loaded_profile_path == profile:
                    additions = current - self.base_profile_patterns
                    exclusions = self.base_profile_patterns - current
                else:
                    additions = current
                    exclusions = set()
                apply_manual_coverage(
                    profile, additions,
                    excluded_patterns=exclusions,
                    action=self.manual_action.get(), layout=self.manual_layout.get(),
                    block_size=self.manual_block.get(),
                )
                self.loaded_profile_path = profile
                if notify:
                    messagebox.showinfo(tr("profile_updated"), tr("manual_saved", path=profile))
                return True
            except (GuiInputError, OSError) as exc:
                messagebox.showerror(tr("profile_update_failed"), str(exc))
                return False

        def _validate_paths(self, *, need_trace: bool = False, need_profile: bool = True) -> tuple[Path, Path, Path, Path]:
            app_root = Path(self.app_root.get()).expanduser().resolve()
            ampr_index = Path(self.ampr_index.get()).expanduser().resolve()
            profile = Path(self.profile.get()).expanduser().resolve()
            output = Path(self.output.get()).expanduser().resolve()
            if not app_root.is_dir():
                raise GuiInputError(tr("app_root_missing", path=app_root))
            if not ampr_index.is_file():
                raise GuiInputError(tr("index_missing", path=ampr_index))
            if need_profile and not profile.is_file():
                raise GuiInputError(tr("profile_missing", path=profile))
            if need_trace:
                discover_trace_pairs(Path(self.trace_root.get()))
            return app_root, ampr_index, profile, output

        def _generate(self, messagebox) -> None:
            try:
                _app_root, _index, profile, _output = self._validate_paths(need_trace=True, need_profile=False)
                if not self._pattern_values() and manual_sidecar_path(profile).is_file():
                    self._insert_patterns(load_manual_patterns(profile))
                profile.parent.mkdir(parents=True, exist_ok=True)
                command = build_profile_command(Path(self.trace_root.get()), profile)
            except (GuiInputError, OSError) as exc:
                messagebox.showerror(tr("source_missing"), str(exc))
                return

            def generated() -> None:
                if self._pattern_values():
                    self._save_manual(messagebox, notify=False)
                self.status.set(tr("profile_created"))

            self._run_pipeline(((tr("profile_generation"), command),), generated, messagebox)

        def _pack_and_verify(self, messagebox) -> None:
            if not self.reviewed.get():
                messagebox.showwarning(
                    tr("coverage_required"),
                    tr("coverage_pack_prompt"),
                )
                return
            try:
                app_root, ampr_index, profile, output = self._validate_paths()
                if not self._save_manual(messagebox, notify=False):
                    return
                output.mkdir(parents=True, exist_ok=True)
                manifest = manifest_path(output, profile)
            except (GuiInputError, OSError, tomllib.TOMLDecodeError) as exc:
                messagebox.showerror(tr("pack_start_failed"), str(exc))
                return
            commands = (
                (tr("packing"), tool_command("pack", "pack", "--root", str(app_root), "--ampr-index", str(ampr_index), "--output", str(output), "--config", str(profile))),
                (tr("full_verify"), tool_command("pack", "verify", "--index", str(manifest), "--root", str(app_root))),
                (tr("manifest_summary"), tool_command("pack", "inspect", "--index", str(manifest))),
            )
            self._run_pipeline(commands, lambda: self.status.set(tr("verified", path=manifest)), messagebox)

        def _verify(self, messagebox) -> None:
            try:
                app_root, _index, profile, output = self._validate_paths()
                manifest = manifest_path(output, profile)
            except (GuiInputError, OSError, tomllib.TOMLDecodeError) as exc:
                messagebox.showerror(tr("verify_start_failed"), str(exc))
                return
            self._run_pipeline(((tr("verify_packs"), tool_command("pack", "verify", "--index", str(manifest), "--root", str(app_root))),), None, messagebox)

        def _inspect(self, messagebox) -> None:
            try:
                _app_root, _index, profile, output = self._validate_paths()
                manifest = manifest_path(output, profile)
            except (GuiInputError, OSError, tomllib.TOMLDecodeError) as exc:
                messagebox.showerror(tr("inspect_failed"), str(exc))
                return
            self._run_pipeline(((tr("manifest_summary"), tool_command("pack", "inspect", "--index", str(manifest))),), None, messagebox)

        def _remove_packed_sources(self, messagebox) -> None:
            if not self.reviewed.get():
                messagebox.showwarning(
                    tr("coverage_required"),
                    tr("coverage_remove_prompt"),
                )
                return
            try:
                app_root, _index, profile, output = self._validate_paths()
                manifest = manifest_path(output, profile)
                from ampr_pack import packed_source_removal_plan

                plan = packed_source_removal_plan(manifest, app_root)
            except (GuiInputError, OSError, RuntimeError, ValueError) as exc:
                messagebox.showerror(tr("remove_prepare_failed"), str(exc))
                return
            files = int(plan["present_files"])
            size = int(plan["bytes"])
            if files == 0:
                messagebox.showinfo(tr("nothing_to_remove"), tr("no_pack_sources"))
                return
            size_mib = size / (1024 * 1024)
            confirmed = messagebox.askyesno(
                tr("permanent_removal"),
                tr("removal_confirm", files=files, size=size_mib, root=app_root),
                icon="warning",
                default="no",
            )
            if not confirmed:
                return
            command = tool_command(
                "pack",
                "remove-packed-sources",
                "--index", str(manifest),
                "--root", str(app_root),
                "--confirm",
            )
            if self.remove_empty_dirs.get():
                command.append("--remove-empty-dirs")
            self._run_pipeline(
                ((tr("remove_sources"), command),),
                lambda: self.status.set(tr("sources_removed", path=app_root)),
                messagebox,
            )

        def _append_log(self, value: str) -> None:
            self.log.configure(state="normal")
            self.log.insert("end", value)
            self.log.see("end")
            self.log.configure(state="disabled")

        def _set_running(self, running: bool) -> None:
            for button in self.action_buttons:
                button.configure(state="disabled" if running else "normal")
            self.cancel_button.configure(state="normal" if running else "disabled")
            self.language_combo.configure(state="disabled" if running else "readonly")

        def _run_pipeline(
            self,
            commands: Sequence[tuple[str, Sequence[str]]],
            on_success: Callable[[], None] | None,
            messagebox,
        ) -> None:
            if self.worker and self.worker.is_alive():
                messagebox.showwarning(tr("already_running"), tr("wait_or_stop"))
                return
            self._set_running(True)
            self.cancel_requested.clear()
            self.status.set(tr("running"))
            self._append_log("\n" + "=" * 72 + "\n")

            def worker() -> None:
                environment = os.environ.copy()
                environment["PYTHONUTF8"] = "1"
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                try:
                    for title, arguments in commands:
                        if self.cancel_requested.is_set():
                            self.events.put(("done", False, tr("operation_stopped"), None))
                            return
                        self.events.put(("log", f"\n[{title}]\n$ " + subprocess.list2cmdline(list(arguments)) + "\n"))
                        self.process = subprocess.Popen(
                            list(arguments), cwd=DISTRIBUTION_ROOT, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", bufsize=1,
                            creationflags=creationflags,
                        )
                        assert self.process.stdout is not None
                        for line in self.process.stdout:
                            self.events.put(("log", line))
                        result = self.process.wait()
                        self.process = None
                        if result != 0:
                            self.events.put(("done", False, tr("exit_code", title=title, code=result), None))
                            return
                    self.events.put(("done", True, tr("operation_success"), on_success))
                except Exception as exc:  # surfaced in the GUI, including launch failures
                    self.process = None
                    self.events.put(("done", False, str(exc), None))

            self.worker = threading.Thread(target=worker, name="ampr-pack-gui-worker", daemon=True)
            self.worker.start()

        def _cancel(self) -> None:
            self.cancel_requested.set()
            process = self.process
            if process is not None and process.poll() is None:
                process.terminate()
                self.status.set(tr("stopping"))

        def _close(self) -> None:
            self.cancel_requested.set()
            process = self.process
            if process is not None and process.poll() is None:
                process.terminate()
            self.destroy()

        def _poll_events(self) -> None:
            try:
                while True:
                    event = self.events.get_nowait()
                    if event[0] == "log":
                        self._append_log(str(event[1]))
                    elif event[0] == "done":
                        success, message, callback = bool(event[1]), str(event[2]), event[3]
                        self._set_running(False)
                        self.status.set(message)
                        if success and callback is not None:
                            callback()
                        elif not success:
                            messagebox.showerror(tr("operation_failed"), message)
            except queue.Empty:
                pass
            self.after(100, self._poll_events)

    app = AssetPackApp()
    app.mainloop()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "--internal-pack":
        from ampr_pack import main as pack_main

        return pack_main(arguments[1:])
    if arguments and arguments[0] == "--internal-profile":
        from ampr_pack_profile import main as profile_main

        return profile_main(arguments[1:])
    language = None
    if arguments and arguments[0] == "--lang":
        if len(arguments) != 2 or arguments[1] not in SUPPORTED_LANGUAGES:
            print("usage: ampr_pack_gui.py [--lang ru|en]", file=sys.stderr)
            return 2
        language = arguments[1]
        arguments.clear()
    elif arguments and arguments[0].startswith("--lang="):
        language = arguments[0].partition("=")[2]
        if len(arguments) != 1 or language not in SUPPORTED_LANGUAGES:
            print("usage: ampr_pack_gui.py [--lang ru|en]", file=sys.stderr)
            return 2
        arguments.clear()
    if arguments:
        print(f"unknown argument: {arguments[0]}", file=sys.stderr)
        return 2
    return run_gui(language)


if __name__ == "__main__":
    # Required when the frozen profiler uses ProcessPoolExecutor on Windows.
    import multiprocessing

    multiprocessing.freeze_support()
    raise SystemExit(main())
