#!/usr/bin/env python3
"""
Домашня робота №11: міні-звіт про ризики встановленого ПЗ.

Скрипт послідовно:
1. самостійно збирає інвентар на Windows, macOS або Linux;
2. випадково вибирає п'ять програм, для яких відома версія;
3. шукає до трьох CVE для кожної вибраної програми;
4. перевіряє знайдені CVE у каталозі CISA KEV;
5. отримує оцінку EPSS для кожної CVE;
6. визначає пріоритет P1-P4;
7. записує результат у CSV, сумісний з Excel.

Пошук NVD за ключовим словом є навчальним спрощенням. Він не доводить,
що знайдена CVE стосується саме встановленої версії програми. Для точної
перевірки у виробничих системах використовують CPE та діапазони версій.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import plistlib
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

import requests
from dotenv import load_dotenv


# Завантажуємо локальний .env, якщо він існує. Справжній ключ NVD не можна
# записувати у код або комітити в Git.
load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_MIRROR_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"

USER_AGENT = "CybersecurityFromScratch-Homework11/1.0 (educational project)"
KEV_CACHE = Path("kev_cache.json")
KEV_CACHE_TTL = 24 * 60 * 60
DEFAULT_INVENTORY_FILE = "inventory.json"
APPS_TO_CHECK = 5
COMMAND_TIMEOUT = 120
CSV_COLUMNS = [
    "app",
    "installed_version",
    "cve_id",
    "cvss",
    "severity",
    "in_kev",
    "epss",
    "priority",
]


def deduplicate_apps(apps: list[dict[str, str]]) -> list[dict[str, str]]:
    """Прибирає дублікати за назвою і версією та сортує інвентар."""
    unique: dict[tuple[str, str], dict[str, str]] = {}

    for app in apps:
        name = app.get("name", "").strip()
        version = app.get("version", "").strip()
        if not name or not version:
            continue

        key = (name.casefold(), version)
        unique.setdefault(
            key,
            {
                "name": name,
                "version": version,
                "vendor": app.get("vendor", "").strip(),
            },
        )

    return sorted(unique.values(), key=lambda item: item["name"].casefold())


def collect_macos_inventory() -> list[dict[str, str]]:
    """
    Збирає назви та версії програм без запуску зовнішніх команд.

    У macOS кожна програма з розширенням .app є каталогом. Її назва, версія
    та ідентифікатор зберігаються у Contents/Info.plist. Стандартний модуль
    plistlib уміє безпечно читати як XML-, так і бінарні plist-файли.
    """
    # /System/Applications навмисно не скануємо: системні програми Apple мають
    # занадто загальні назви на кшталт Mail або Books і створюють багато шуму.
    search_paths = [Path("/Applications"), Path.home() / "Applications"]
    apps: list[dict[str, str]] = []

    for base in search_paths:
        if not base.exists():
            continue

        try:
            # Другий шаблон знаходить програми в каталогах Utilities тощо.
            app_paths = list(base.glob("*.app")) + list(base.glob("*/*.app"))
        except OSError as error:
            print(f"  Не вдалося прочитати {base}: {error}", file=sys.stderr)
            continue

        for app_path in app_paths:
            plist_path = app_path / "Contents" / "Info.plist"
            if not plist_path.exists():
                continue

            try:
                with open(plist_path, "rb") as plist_file:
                    info = plistlib.load(plist_file)
            except (
                OSError,
                plistlib.InvalidFileException,
                ExpatError,
                ValueError,
                TypeError,
            ):
                # Один пошкоджений або недоступний застосунок не повинен
                # зупиняти інвентаризацію всього комп'ютера.
                continue

            if not isinstance(info, dict):
                continue

            name = str(
                info.get("CFBundleDisplayName")
                or info.get("CFBundleName")
                or app_path.stem
            ).strip()
            version = str(
                info.get("CFBundleShortVersionString")
                or info.get("CFBundleVersion")
                or ""
            ).strip()
            vendor = str(info.get("CFBundleIdentifier") or "").strip()

            if name and version:
                apps.append({"name": name, "version": version, "vendor": vendor})

    # Одна програма може бути одночасно в /Applications і ~/Applications.
    return deduplicate_apps(apps)


def collect_windows_inventory() -> list[dict[str, str]]:
    """
    Читає встановлені програми з реєстру Windows стандартним модулем winreg.

    Перевіряються системні та користувацькі гілки, а також 64- і 32-бітні
    представлення реєстру. Зовнішній PowerShell не запускається.
    """
    try:
        import winreg
    except ImportError as error:
        raise OSError("Модуль winreg недоступний поза Windows") from error

    uninstall_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    views = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)
    roots = (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER)
    apps: list[dict[str, str]] = []

    def read_registry_value(key: Any, name: str) -> str:
        """Повертає текстове значення реєстру або порожній рядок."""
        try:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value).strip()
        except OSError:
            return ""

    for root in roots:
        for view in views:
            try:
                with winreg.OpenKey(
                    root,
                    uninstall_path,
                    0,
                    winreg.KEY_READ | view,
                ) as uninstall_key:
                    subkey_count = winreg.QueryInfoKey(uninstall_key)[0]

                    for index in range(subkey_count):
                        try:
                            subkey_name = winreg.EnumKey(uninstall_key, index)
                            with winreg.OpenKey(uninstall_key, subkey_name) as app_key:
                                name = read_registry_value(app_key, "DisplayName")
                                version = read_registry_value(app_key, "DisplayVersion")
                                vendor = read_registry_value(app_key, "Publisher")
                        except OSError:
                            continue

                        if name and version:
                            apps.append(
                                {"name": name, "version": version, "vendor": vendor}
                            )
            except OSError:
                # Частина гілок може не існувати або бути недоступною без
                # адміністративних прав; решту інвентарю все одно збираємо.
                continue

    return deduplicate_apps(apps)


def run_command(command: list[str]) -> str:
    """
    Безпечно запускає команду пакетного менеджера без shell=True.

    Аргументи передаються списком напряму процесу, тому символи оболонки у
    назвах пакетів не можуть перетворитися на ін'єкцію команд.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""

    return result.stdout if result.returncode == 0 else ""


def collect_linux_inventory() -> list[dict[str, str]]:
    """Збирає пакети через перший доступний менеджер: dpkg, rpm або pacman."""
    commands = [
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
        ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
        ["pacman", "-Q"],
    ]

    for command in commands:
        output = run_command(command)
        if not output.strip():
            continue

        apps: list[dict[str, str]] = []
        for line in output.splitlines():
            # dpkg і rpm розділяють поля табуляцією, pacman — пробілом.
            parts = line.split("\t", 1) if "\t" in line else line.split(" ", 1)
            if len(parts) != 2:
                continue

            name, version = (part.strip() for part in parts)
            if name and version:
                apps.append({"name": name, "version": version, "vendor": ""})

        if apps:
            return deduplicate_apps(apps)

    return []


def collect_inventory() -> list[dict[str, str]]:
    """Визначає операційну систему та викликає відповідний інвентаризатор."""
    system = platform.system()

    if system == "Darwin":
        return collect_macos_inventory()
    if system == "Windows":
        return collect_windows_inventory()
    if system == "Linux":
        return collect_linux_inventory()

    raise OSError(f"Непідтримувана операційна система: {system}")


def save_inventory(apps: list[dict[str, str]], filename: str) -> None:
    """Зберігає повний інвентар у читабельному UTF-8 JSON."""
    Path(filename).write_text(
        json.dumps(apps, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def select_random_apps(
    inventory: list[dict[str, str]],
    count: int = APPS_TO_CHECK,
) -> list[dict[str, str]]:
    """Випадково вибирає програми не від Apple, що мають назву та версію."""
    candidates = [
        app
        for app in inventory
        if app.get("name")
        and app.get("version")
        and not app.get("vendor", "").startswith("com.apple")
    ]

    if len(candidates) < count:
        raise ValueError(
            f"Для випадкового вибору потрібно {count} програм, знайдено {len(candidates)}"
        )

    # SystemRandom використовує системне джерело випадковості. На відміну від
    # звичайного random, вибір не повторюється через випадково однаковий seed.
    selected = secrets.SystemRandom().sample(candidates, count)

    # У наступних функціях поле vendor не потрібне, тому повертаємо просту
    # структуру рівно з назвою та встановленою версією.
    return [
        {"name": app["name"], "version": app["version"]}
        for app in selected
    ]


def nvd_delay() -> float:
    """Повертає безпечну паузу між запитами до NVD."""
    return 0.6 if os.environ.get("NVD_API_KEY") else 6.0


def nvd_headers() -> dict[str, str]:
    """Формує заголовки NVD і додає API-ключ лише за його наявності."""
    headers = {"User-Agent": USER_AGENT}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str]:
    """
    Дістає найновішу доступну оцінку CVSS.

    Не кожна CVE має оцінку NVD, тому відсутність даних повертається як
    (None, ""), а не спричиняє падіння скрипту.
    """
    versions = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

    for version in versions:
        entries = metrics.get(version) or []
        if not entries:
            continue

        entry = entries[0]
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""

        try:
            parsed_score = float(score) if score is not None else None
        except (TypeError, ValueError):
            parsed_score = None

        return parsed_score, str(severity)

    return None, ""


def search_nvd(app: dict[str, str], limit: int = 3) -> list[dict[str, Any]]:
    """Шукає не більше трьох CVE для однієї програми через NVD API 2.0."""
    # Захищаємо вимогу завдання навіть від випадкового неправильного виклику.
    safe_limit = max(0, min(limit, 3))
    if safe_limit == 0:
        return []

    params = {
        "keywordSearch": app["name"],
        "resultsPerPage": str(safe_limit),
    }

    try:
        response = requests.get(
            NVD_URL,
            params=params,
            headers=nvd_headers(),
            timeout=60,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.exceptions.RequestException as error:
        print(f"    NVD недоступний: {error}", file=sys.stderr)
        return []
    except (ValueError, TypeError) as error:
        print(f"    NVD повернув некоректний JSON: {error}", file=sys.stderr)
        return []

    rows: list[dict[str, Any]] = []

    for item in payload.get("vulnerabilities", [])[:safe_limit]:
        cve = item.get("cve") or {}
        cve_id = cve.get("id") or ""
        if not cve_id:
            continue

        score, severity = extract_cvss(cve.get("metrics") or {})
        rows.append(
            {
                "app": app["name"],
                "installed_version": app["version"],
                "cve_id": cve_id,
                "cvss": score,
                "severity": severity,
                # Значення нижче заповнюються після запитів до KEV та EPSS.
                "in_kev": False,
                "epss": 0.0,
                "priority": "P4",
            }
        )

    return rows


def read_fresh_kev_cache() -> dict[str, Any] | None:
    """Читає кеш KEV, лише якщо він молодший за одну добу та має валідний JSON."""
    if not KEV_CACHE.exists():
        return None

    try:
        age = time.time() - KEV_CACHE.stat().st_mtime
        if age >= KEV_CACHE_TTL:
            return None
        return json.loads(KEV_CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def load_kev() -> set[str]:
    """Завантажує CISA KEV та повертає множину ідентифікаторів CVE."""
    payload = read_fresh_kev_cache()

    if payload is None:
        for url in (KEV_URL, KEV_MIRROR_URL):
            try:
                response = requests.get(
                    url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=60,
                )
                response.raise_for_status()
                payload = response.json()
                KEV_CACHE.write_text(json.dumps(payload), encoding="utf-8")
                break
            except requests.exceptions.RequestException as error:
                print(f"  KEV недоступний через {url}: {error}", file=sys.stderr)
            except (OSError, ValueError, TypeError) as error:
                print(f"  Не вдалося обробити KEV: {error}", file=sys.stderr)

    if not isinstance(payload, dict):
        print("  Продовжую без даних KEV.", file=sys.stderr)
        return set()

    return {
        str(item["cveID"])
        for item in payload.get("vulnerabilities", [])
        if isinstance(item, dict) and item.get("cveID")
    }


def load_epss(cve_ids: list[str]) -> dict[str, float]:
    """Отримує EPSS для унікальних CVE пачками до 100 ідентифікаторів."""
    unique_ids = list(dict.fromkeys(cve_ids))
    scores: dict[str, float] = {}

    for start in range(0, len(unique_ids), 100):
        batch = unique_ids[start : start + 100]
        if not batch:
            continue

        try:
            response = requests.get(
                EPSS_URL,
                params={"cve": ",".join(batch)},
                headers={"User-Agent": USER_AGENT},
                timeout=60,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.RequestException as error:
            print(f"  EPSS недоступний: {error}", file=sys.stderr)
            continue
        except (ValueError, TypeError) as error:
            print(f"  EPSS повернув некоректний JSON: {error}", file=sys.stderr)
            continue

        for item in payload.get("data", []):
            try:
                scores[str(item["cve"])] = float(item["epss"])
            except (KeyError, TypeError, ValueError):
                # Один пошкоджений елемент не повинен зупиняти весь звіт.
                continue

        # EPSS не має жорсткого ліміту, але невелика пауза є коректною
        # поведінкою клієнта. Після останньої пачки чекати вже не потрібно.
        if start + 100 < len(unique_ids):
            time.sleep(0.5)

    return scores


def get_priority(in_kev: bool, epss: float, cvss: float | None) -> str:
    """Визначає пріоритет строго за правилами домашнього завдання."""
    if in_kev:
        return "P1"
    if epss >= 0.5:
        return "P2"
    if epss >= 0.1:
        return "P3"
    if cvss is not None and cvss >= 9.0:
        return "P3"
    return "P4"


def save_csv(rows: list[dict[str, Any]], filename: str) -> None:
    """Зберігає CSV з фіксованими колонками та BOM для коректного Excel."""
    with open(filename, "w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        # Заголовок записується навіть для порожнього результату.
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Побудова звіту NVD + KEV + EPSS")
    parser.add_argument("--out", default="risk_report.csv", help="шлях до CSV-звіту")
    parser.add_argument(
        "--inventory-out",
        default=DEFAULT_INVENTORY_FILE,
        help="шлях до повного JSON-інвентарю",
    )
    args = parser.parse_args()

    print("Домашня робота №11: звіт про ризики")
    print(f"Операційна система: {platform.system()} {platform.release()}")
    print("Збираю інвентар установлених програм...")

    try:
        inventory = collect_inventory()
        if not inventory:
            raise ValueError("не знайдено жодної програми з відомою версією")
        save_inventory(inventory, args.inventory_out)
        selected_apps = select_random_apps(inventory)
    except (OSError, ValueError) as error:
        print(f"Помилка інвентаризації: {error}", file=sys.stderr)
        return 1

    delay = nvd_delay()
    print(f"Знайдено програм: {len(inventory)}")
    print(f"Інвентар збережено у {args.inventory_out}")
    print(f"Випадково вибрано програм: {len(selected_apps)}")
    print(f"Пауза між запитами NVD: {delay} с\n")

    rows: list[dict[str, Any]] = []

    for index, app in enumerate(selected_apps, start=1):
        print(f"[{index}/{len(selected_apps)}] {app['name']} {app['version']}")
        findings = search_nvd(app, limit=3)
        rows.extend(findings)
        print(f"    знайдено CVE: {len(findings)}")

        # NVD без API-ключа дозволяє лише 5 запитів за 30 секунд. Тому між
        # запитами обов'язково чекаємо 6 секунд; після останнього не чекаємо.
        if index < len(selected_apps):
            time.sleep(delay)

    if rows:
        print("\nПеревіряю CISA KEV...")
        kev_ids = load_kev()
        print(f"  записів у KEV: {len(kev_ids)}")

        cve_ids = [str(row["cve_id"]) for row in rows]
        print(f"Отримую EPSS для {len(set(cve_ids))} унікальних CVE...")
        epss_scores = load_epss(cve_ids)
        print(f"  отримано оцінок EPSS: {len(epss_scores)}")

        for row in rows:
            cve_id = str(row["cve_id"])
            row["in_kev"] = cve_id in kev_ids
            row["epss"] = epss_scores.get(cve_id, 0.0)
            row["priority"] = get_priority(
                bool(row["in_kev"]),
                float(row["epss"]),
                row["cvss"],
            )

        # P1, P2, P3, P4 сортуються лексикографічно у потрібному порядку.
        rows.sort(key=lambda row: (row["priority"], -float(row["epss"])))
    else:
        print("\nNVD не повернув жодної CVE; буде створено CSV лише із заголовком.")

    save_csv(rows, args.out)

    counts = {priority: 0 for priority in ("P1", "P2", "P3", "P4")}
    for row in rows:
        counts[str(row["priority"])] += 1

    print(f"\nЗбережено рядків: {len(rows)} у {args.out}")
    print("Пріоритети: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
