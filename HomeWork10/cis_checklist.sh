#!/usr/bin/env bash
#
# cis_checklist.sh — спрощений навчальний CIS checklist.
#
# Скрипт нічого не змінює в системі: він лише читає налаштування та показує
# PASS, FAIL або SKIP. Для повнішого звіту в Linux можна запустити через sudo,
# але всі перевірки залишаються read-only.
#
# Це не офіційний CIS Benchmark і не замінює повний аудит безпеки.
#
# ЯК ЗАПУСТИТИ:
#   chmod +x cis_checklist.sh   # один раз додати право на виконання
#   ./cis_checklist.sh          # звичайна перевірка без зміни системи
#   sudo ./cis_checklist.sh     # повніший звіт для захищених конфігів Linux
#
# Запуск без кольорів (зручно для запису у файл або CI):
#   NO_COLOR=1 ./cis_checklist.sh
#   ./cis_checklist.sh | tee cis_report.txt
#
# Переглянути код завершення одразу після запуску:
#   echo $?
#   0 — немає FAIL (але можуть бути SKIP), 1 — є хоча б один FAIL.
#
# ЯК ЧИТАТИ РЕЗУЛЬТАТ:
#   PASS — налаштування відповідає цій спрощеній перевірці;
#   FAIL — налаштування знайдено, але воно небезпечне або відсутнє;
#   SKIP — скрипт не може зробити надійний висновок (бракує прав, команди
#          чи явного параметра). SKIP треба перевірити вручну, це не PASS.

set -euo pipefail

# --- Кольори та лічильники -----------------------------------------------

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    # Колір 208 із 256-кольорової ANSI-палітри — помаранчевий.
    ORANGE=$'\033[38;5;208m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    ORANGE=""
    BOLD=""
    RESET=""
fi

pass_count=0
fail_count=0
skip_count=0

# Назви й статуси зберігаються парами з однаковими індексами. Це дає змогу
# повторно показати всі результати одним списком у фінальному підсумку.
check_statuses=()
check_labels=()

have() {
    command -v "$1" >/dev/null 2>&1
}

print_recommendation() {
    local recommendation="$1"
    local line
    local command

    printf '         %sРекомендація:%s\n' "$YELLOW" "$RESET"
    while IFS= read -r line; do
        # Рядки з префіксом CMD: оформлюємо як окремі команди.
        if [[ "$line" == CMD:* ]]; then
            command="${line#CMD: }"
            printf '           %s$ %s%s\n' "$ORANGE" "$command" "$RESET"
        else
            printf '           %s\n' "$line"
        fi
    done <<< "$recommendation"
}

result() {
    local state="$1"
    local label="$2"
    local detail="${3:-}"
    local recommendation="${4:-}"
    local color=""

    case "$state" in
        PASS)
            color="$GREEN"
            pass_count=$((pass_count + 1))
            ;;
        FAIL)
            color="$RED"
            fail_count=$((fail_count + 1))
            ;;
        SKIP)
            color="$YELLOW"
            skip_count=$((skip_count + 1))
            ;;
        *)
            printf 'Невідомий статус: %s\n' "$state" >&2
            return 1
            ;;
    esac

    check_statuses+=("$state")
    check_labels+=("$label")

    printf '  %s[%s]%s %s' "$color" "$state" "$RESET" "$label"
    if [[ -n "$detail" ]]; then
        printf ' — %s' "$detail"
    fi
    printf '\n'

    # Рекомендацію показуємо лише для пунктів, які потребують уваги.
    if [[ "$state" != "PASS" && -n "$recommendation" ]]; then
        print_recommendation "$recommendation"
    fi
}

section() {
    printf '\n%s%s%s\n' "$BOLD$BLUE" "$1" "$RESET"
}

# --- Визначення платформи ------------------------------------------------

detect_platform() {
    case "$(uname -s)" in
        Linux*)
            if grep -qi microsoft /proc/version 2>/dev/null ||
                grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
                PLATFORM="wsl"
                PLATFORM_NAME="WSL"
            else
                PLATFORM="linux"
                PLATFORM_NAME="Linux"
            fi
            ;;
        Darwin*)
            PLATFORM="macos"
            PLATFORM_NAME="macOS"
            ;;
        *)
            printf 'Непідтримувана платформа: %s\n' "$(uname -s)" >&2
            exit 1
            ;;
    esac
}

# Короткі поради для консольного звіту. Детальні кроки та попередження
# залишаються в коментарях біля відповідної перевірки.
password_recommendation() {
    case "$PLATFORM" in
        macos)
            printf '%s\n' \
                'Задайте мінімум 8 символів через MDM/configuration profile.' \
                'Перевірити чинну локальну політику:' \
                'CMD: pwpolicy -getglobalpolicy'
            ;;
        wsl)
            printf '%s\n' \
                'Установіть libpam-pwquality всередині WSL:' \
                'CMD: sudo apt update' \
                'CMD: sudo apt install libpam-pwquality' \
                'Відкрийте /etc/security/pwquality.conf і задайте minlen = 8.' \
                'Пароль облікового запису Windows налаштовується окремо.'
            ;;
        *)
            if have apt-get; then
                printf '%s\n' \
                    'Установіть і налаштуйте libpam-pwquality:' \
                    'CMD: sudo apt update' \
                    'CMD: sudo apt install libpam-pwquality' \
                    'CMD: sudoedit /etc/security/pwquality.conf' \
                    'У конфігурації задайте minlen = 8 або більше.'
            elif have dnf; then
                printf '%s\n' \
                    'Установіть і налаштуйте libpwquality:' \
                    'CMD: sudo dnf install libpwquality' \
                    'CMD: sudoedit /etc/security/pwquality.conf' \
                    'У конфігурації задайте minlen = 8 або більше.'
            else
                printf '%s' 'Налаштуйте PAM/libpwquality і явно задайте minlen не менше 8.'
            fi
            ;;
    esac
}

firewall_recommendation() {
    case "$PLATFORM" in
        macos)
            printf '%s' 'Увімкніть System Settings -> Network -> Firewall і повторіть перевірку.'
            ;;
        wsl)
            if have apt-get; then
                printf '%s\n' \
                    'Установіть і ввімкніть UFW усередині WSL:' \
                    'CMD: sudo apt update' \
                    'CMD: sudo apt install ufw' \
                    'CMD: sudo ufw enable' \
                    'Також перевірте Windows Defender Firewall у Windows.'
            else
                printf '%s\n' \
                    'Установіть UFW пакетним менеджером дистрибутива.' \
                    'CMD: sudo ufw enable' \
                    'Також перевірте Windows Defender Firewall у Windows.'
            fi
            ;;
        *)
            if have apt-get; then
                printf '%s\n' \
                    'Установіть UFW і задайте базові правила:' \
                    'CMD: sudo apt update' \
                    'CMD: sudo apt install ufw' \
                    'CMD: sudo ufw default deny incoming' \
                    'CMD: sudo ufw default allow outgoing' \
                    'Якщо потрібен віддалений SSH, дозвольте його ДО активації:' \
                    'CMD: sudo ufw allow OpenSSH' \
                    'Після перевірки правил увімкніть фаєрвол:' \
                    'CMD: sudo ufw enable'
            elif have dnf; then
                printf '%s\n' \
                    'Для Fedora/RHEL типовим є firewalld:' \
                    'CMD: sudo dnf install firewalld' \
                    'CMD: sudo systemctl enable --now firewalld' \
                    'CMD: sudo firewall-cmd --state' \
                    'Цей спрощений пункт перевіряє UFW, тому firewalld оцініть вручну.'
            else
                printf '%s\n' \
                    'Установіть UFW пакетним менеджером системи.' \
                    'Перед активацією дозвольте SSH, якщо працюєте віддалено.' \
                    'CMD: sudo ufw enable'
            fi
            ;;
    esac
}

ssh_recommendation() {
    case "$PLATFORM" in
        macos)
            printf '%s\n' \
                'Задайте PermitRootLogin no у конфігурації SSH.' \
                'CMD: sudo sshd -t' \
                'Після успішної перевірки перезапустіть Remote Login.' \
                'Не закривайте чинну сесію до перевірки нового входу.'
            ;;
        wsl)
            printf '%s\n' \
                'Задайте PermitRootLogin no у конфігурації SSH WSL.' \
                'CMD: sudo sshd -t' \
                'Після успішної перевірки перечитайте конфіг сервісу SSH.'
            ;;
        *)
            printf '%s\n' \
                'Задайте PermitRootLogin no у конфігурації SSH.' \
                'CMD: sudo sshd -t' \
                'Якщо синтаксис правильний:' \
                'CMD: sudo systemctl reload ssh' \
                'Не закривайте чинну сесію до перевірки нового входу.'
            ;;
    esac
}

updates_recommendation() {
    case "$PLATFORM" in
        macos)
            printf '%s' 'Увімкніть Automatic Updates у System Settings -> General -> Software Update.'
            ;;
        wsl)
            if have apt-get; then
                printf '%s\n' \
                    'Увімкніть unattended-upgrades усередині WSL:' \
                    'CMD: sudo apt update' \
                    'CMD: sudo apt install unattended-upgrades' \
                    'CMD: sudo dpkg-reconfigure -plow unattended-upgrades' \
                    'Окремо перевірте Windows Update.'
            elif have dnf; then
                printf '%s\n' \
                    'Увімкніть dnf-automatic усередині WSL:' \
                    'CMD: sudo dnf install dnf-automatic' \
                    'CMD: sudo systemctl enable --now dnf-automatic.timer' \
                    'Окремо перевірте Windows Update.'
            else
                printf '%s' 'Увімкніть штатний механізм автооновлень дистрибутива WSL та окремо перевірте Windows Update.'
            fi
            ;;
        *)
            if have apt-get; then
                printf '%s\n' \
                    'Установіть і ввімкніть unattended-upgrades:' \
                    'CMD: sudo apt update' \
                    'CMD: sudo apt install unattended-upgrades' \
                    'CMD: sudo dpkg-reconfigure -plow unattended-upgrades'
            elif have dnf; then
                printf '%s\n' \
                    'Установіть і ввімкніть dnf-automatic:' \
                    'CMD: sudo dnf install dnf-automatic' \
                    'CMD: sudo systemctl enable --now dnf-automatic.timer'
            else
                printf '%s' 'Увімкніть штатний механізм автоматичного встановлення оновлень безпеки.'
            fi
            ;;
    esac
}

lockout_recommendation() {
    case "$PLATFORM" in
        macos)
            printf '%s\n' \
                'Задайте максимальну кількість невдалих входів через MDM/configuration profile.' \
                'Перевірити чинну локальну політику:' \
                'CMD: pwpolicy -getglobalpolicy'
            ;;
        wsl)
            printf '%s\n' \
                'Налаштуйте pam_faillock і deny=N усередині WSL:' \
                'CMD: sudoedit /etc/security/faillock.conf' \
                'Політика блокування Windows-акаунта задається окремо.'
            ;;
        *)
            printf '%s\n' \
                'Налаштуйте pam_faillock і deny=N:' \
                'CMD: sudoedit /etc/security/faillock.conf' \
                'Перед зміною PAM зробіть резервну копію та залиште root-консоль.'
            ;;
    esac
}

# --- 1. Мінімальна довжина пароля ---------------------------------------
#
# ЩО РОБИТИ ПРИ FAIL АБО SKIP:
#
# Linux (Ubuntu/Debian):
#   1. Встановити модуль, якщо його немає:
#        sudo apt install libpam-pwquality
#   2. У /etc/security/pwquality.conf явно задати:
#        minlen = 8
#      Можна вибрати більше значення, наприклад 12 або 14.
#   3. Переконатися, що /etc/pam.d/common-password використовує
#      pam_pwquality.so. Перед редагуванням PAM обов'язково зробити резервну
#      копію: помилка в PAM може заблокувати вхід у систему.
#
# Linux (Fedora/RHEL):
#   Встановити libpwquality та задати minlen у /etc/security/pwquality.conf:
#        sudo dnf install libpwquality
#
# macOS:
#   SKIP означає, що pwpolicy не повернула старий параметр minChars. На нових
#   версіях macOS парольну політику краще задавати через MDM/configuration
#   profile. Для локальної перевірки дивіться `man pwpolicy` та чинні профілі.
#
# WSL:
#   Виконати кроки для Linux-дистрибутива всередині WSL. Ця політика впливає
#   лише на Linux-користувачів WSL, а не на пароль облікового запису Windows.

check_password_length_linux() {
    local value=""
    local file
    local -a config_files=()
    local -a pam_files=()

    # libpwquality зберігає minlen в основному файлі або у фрагментах *.conf.
    if [[ -r /etc/security/pwquality.conf ]]; then
        config_files+=(/etc/security/pwquality.conf)
    fi
    for file in /etc/security/pwquality.conf.d/*.conf; do
        [[ -r "$file" ]] && config_files+=("$file")
    done

    if (( ${#config_files[@]} > 0 )); then
        value=$(awk -F= '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*minlen[[:space:]]*=/ {
                gsub(/[[:space:]]/, "", $2)
                last=$2
            }
            END { print last }
        ' "${config_files[@]}")
    fi

    # Параметр також може бути записаний прямо біля pam_pwquality.so.
    if [[ -z "$value" ]]; then
        for file in /etc/pam.d/common-password /etc/pam.d/system-auth \
            /etc/pam.d/password-auth; do
            [[ -r "$file" ]] && pam_files+=("$file")
        done
        if (( ${#pam_files[@]} > 0 )); then
            value=$(grep -Eho 'minlen[[:space:]]*=[[:space:]]*[0-9]+' \
                "${pam_files[@]}" 2>/dev/null | tail -1 | tr -cd '0-9' || true)
        fi
    fi

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        result SKIP "Мінімальна довжина пароля" \
            "minlen не задано явно або конфіг недоступний" "$(password_recommendation)"
    elif (( value >= 8 )); then
        result PASS "Мінімальна довжина пароля" "minlen=$value (потрібно не менше 8)"
    else
        result FAIL "Мінімальна довжина пароля" \
            "minlen=$value (потрібно не менше 8)" "$(password_recommendation)"
    fi
}

check_password_length_macos() {
    local policy=""
    local value=""

    if have pwpolicy; then
        policy=$(pwpolicy -getglobalpolicy 2>/dev/null || true)
        value=$(printf '%s\n' "$policy" | grep -Eo 'minChars=[0-9]+' | \
            tail -1 | cut -d= -f2 || true)
    fi

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        result SKIP "Мінімальна довжина пароля" \
            "macOS не показала minChars у глобальній політиці" "$(password_recommendation)"
    elif (( value >= 8 )); then
        result PASS "Мінімальна довжина пароля" "minChars=$value"
    else
        result FAIL "Мінімальна довжина пароля" \
            "minChars=$value (потрібно не менше 8)" "$(password_recommendation)"
    fi
}

check_password_length() {
    section "1. Парольна політика"
    if [[ "$PLATFORM" == "macos" ]]; then
        check_password_length_macos
    else
        check_password_length_linux
    fi
}

# --- 2. Фаєрвол ----------------------------------------------------------
#
# ЩО РОБИТИ ПРИ FAIL АБО SKIP:
#
# Linux (Ubuntu/Debian):
#   Встановити та увімкнути UFW:
#        sudo apt install ufw
#        sudo ufw default deny incoming
#        sudo ufw default allow outgoing
#        sudo ufw enable
#   Якщо комп'ютер адмініструється через SSH, ДО `ufw enable` спочатку
#   дозволити SSH (`sudo ufw allow OpenSSH`) і не закривати поточну сесію,
#   доки нове підключення не буде перевірено.
#   SKIP зазвичай означає нестачу прав — повторити аудит через sudo.
#
# Linux (Fedora/RHEL):
#   Цей спрощений пункт перевіряє саме UFW. У Fedora/RHEL типовим є firewalld;
#   його слід перевірити окремо командою `sudo firewall-cmd --state`.
#
# macOS:
#   Увімкнути: System Settings -> Network -> Firewall. Після цього повторити
#   перевірку. SKIP означає, що socketfilterfw відсутній або стан недоступний.
#
# WSL:
#   UFW захищає Linux-середовище лише частково. Також обов'язково перевірити
#   Windows Defender Firewall у Windows Security, бо саме Windows керує
#   основним мережевим периметром WSL.

check_firewall() {
    local output=""
    local socketfilterfw="/usr/libexec/ApplicationFirewall/socketfilterfw"

    section "2. Фаєрвол"

    if [[ "$PLATFORM" == "macos" ]]; then
        if [[ ! -x "$socketfilterfw" ]]; then
            result SKIP "Application Firewall" "socketfilterfw не знайдено" \
                "$(firewall_recommendation)"
        elif output=$("$socketfilterfw" --getglobalstate 2>/dev/null); then
            if printf '%s\n' "$output" | grep -qi 'enabled'; then
                result PASS "Application Firewall" "$output"
            else
                result FAIL "Application Firewall" "$output" "$(firewall_recommendation)"
            fi
        else
            result SKIP "Application Firewall" "не вдалося прочитати стан" \
                "$(firewall_recommendation)"
        fi
        return
    fi

    if ! have ufw; then
        result FAIL "Фаєрвол UFW" "ufw не встановлено" "$(firewall_recommendation)"
        return
    fi

    output=$(ufw status 2>&1 || true)
    if printf '%s\n' "$output" | grep -qi '^Status:[[:space:]]*active'; then
        result PASS "Фаєрвол UFW" "активний"
    elif printf '%s\n' "$output" | grep -qi '^Status:[[:space:]]*inactive'; then
        result FAIL "Фаєрвол UFW" "неактивний" "$(firewall_recommendation)"
    else
        result SKIP "Фаєрвол UFW" "стан недоступний; запустіть аудит через sudo" \
            "$(firewall_recommendation)"
    fi
}

# --- 3. Заборона root-входу через SSH -----------------------------------
#
# ЩО РОБИТИ ПРИ FAIL АБО SKIP:
#
# Linux:
#   1. У /etc/ssh/sshd_config або окремому файлі в sshd_config.d задати:
#        PermitRootLogin no
#   2. ДО перезапуску перевірити синтаксис:
#        sudo sshd -t
#   3. Якщо помилок немає, перечитати конфіг:
#        sudo systemctl reload ssh
#      У деяких дистрибутивах сервіс називається sshd.
#   Не закривати поточну SSH-сесію, поки вхід звичайним користувачем і sudo
#   не перевірено — інакше можна втратити віддалений доступ.
#
# macOS:
#   Remote Login використовує OpenSSH і /etc/ssh/sshd_config. Задати
#   PermitRootLogin no, виконати `sudo sshd -t`, а потім вимкнути та знову
#   увімкнути Remote Login у System Settings -> General -> Sharing.
#   Якщо Remote Login взагалі не потрібен, безпечніше залишити його вимкненим.
#
# WSL:
#   Якщо openssh-server не використовується — вимкнути або видалити його.
#   Якщо використовується — виконати Linux-кроки та перезапустити сервіс SSH
#   способом, який підтримує конкретна конфігурація WSL/systemd.

check_ssh_root_login() {
    local value=""
    local file
    local -a ssh_files=()

    section "3. Вхід root через SSH"

    # sshd -T показує ефективну конфігурацію і точніше за ручний grep.
    if have sshd; then
        value=$(sshd -T 2>/dev/null | \
            awk '$1 == "permitrootlogin" { print $2; exit }' || true)
    fi

    # Якщо sshd -T недоступний, читаємо конфігураційні файли напряму.
    if [[ -z "$value" ]]; then
        [[ -r /etc/ssh/sshd_config ]] && ssh_files+=(/etc/ssh/sshd_config)
        for file in /etc/ssh/sshd_config.d/*.conf; do
            [[ -r "$file" ]] && ssh_files+=("$file")
        done
        if (( ${#ssh_files[@]} > 0 )); then
            value=$(awk '
                /^[[:space:]]*#/ { next }
                tolower($1) == "permitrootlogin" { print tolower($2); exit }
            ' "${ssh_files[@]}")
        fi
    fi

    if [[ "$value" == "no" ]]; then
        result PASS "SSH: PermitRootLogin" "no — вхід root заборонено"
    elif [[ -n "$value" ]]; then
        result FAIL "SSH: PermitRootLogin" "$value (має бути no)" \
            "$(ssh_recommendation)"
    elif ! have sshd && [[ ! -e /etc/ssh/sshd_config ]]; then
        result PASS "SSH: вхід root" "SSH-сервер не встановлено"
    else
        result FAIL "SSH: PermitRootLogin" "значення no не задано явно" \
            "$(ssh_recommendation)"
    fi
}

# --- 4. Автоматичні оновлення -------------------------------------------
#
# ЩО РОБИТИ ПРИ FAIL АБО SKIP:
#
# Linux (Ubuntu/Debian):
#   Встановити та увімкнути unattended-upgrades:
#        sudo apt update
#        sudo apt install unattended-upgrades
#        sudo dpkg-reconfigure -plow unattended-upgrades
#   Після цього перевірити, що APT::Periodic::Unattended-Upgrade має значення
#   "1" у /etc/apt/apt.conf.d/20auto-upgrades.
#
# Linux (Fedora/RHEL):
#   Встановити dnf-automatic і ввімкнути таймер:
#        sudo dnf install dnf-automatic
#        sudo systemctl enable --now dnf-automatic.timer
#   Для старих систем із yum перевірити apply_updates=yes у yum-cron.conf.
#
# macOS:
#   Відкрити System Settings -> General -> Software Update -> Automatic
#   Updates та ввімкнути автоматичну перевірку й встановлення оновлень безпеки.
#   SKIP означає, що системний параметр недоступний поточному користувачу.
#
# WSL:
#   Налаштувати оновлення всередині Linux-дистрибутива так само, як на Linux.
#   Оновлення Windows і самого WSL налаштовуються окремо через Windows Update.

check_automatic_updates() {
    local config=""
    local value=""

    section "4. Автоматичні оновлення"

    if [[ "$PLATFORM" == "macos" ]]; then
        value=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate \
            AutomaticCheckEnabled 2>/dev/null || true)
        if [[ "$value" == "1" ]]; then
            result PASS "Автоматична перевірка оновлень" "увімкнена"
        elif [[ "$value" == "0" ]]; then
            result FAIL "Автоматична перевірка оновлень" "вимкнена" \
                "$(updates_recommendation)"
        else
            result SKIP "Автоматична перевірка оновлень" "стан недоступний" \
                "$(updates_recommendation)"
        fi
        return
    fi

    if have apt-config; then
        config=$(apt-config dump 2>/dev/null || true)
        if printf '%s\n' "$config" | \
            grep -Eq '^APT::Periodic::Unattended-Upgrade[[:space:]]+"1"'; then
            result PASS "Автоматичні оновлення" "APT unattended-upgrades увімкнено"
        else
            result FAIL "Автоматичні оновлення" \
                "APT Unattended-Upgrade не дорівнює 1" "$(updates_recommendation)"
        fi
    elif have systemctl && systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
        result PASS "Автоматичні оновлення" "dnf-automatic.timer увімкнено"
    elif [[ -r /etc/yum/yum-cron.conf ]]; then
        value=$(awk -F= '
            /^[[:space:]]*apply_updates[[:space:]]*=/ {
                gsub(/[[:space:]]/, "", $2)
                print tolower($2)
                exit
            }
        ' /etc/yum/yum-cron.conf)
        if [[ "$value" == "yes" ]]; then
            result PASS "Автоматичні оновлення" "yum-cron apply_updates=yes"
        else
            result FAIL "Автоматичні оновлення" "yum-cron не застосовує оновлення" \
                "$(updates_recommendation)"
        fi
    else
        result SKIP "Автоматичні оновлення" "відомий механізм не знайдено" \
            "$(updates_recommendation)"
    fi
}

# --- 5. Блокування після невдалих входів --------------------------------
#
# ЩО РОБИТИ ПРИ FAIL АБО SKIP:
#
# Linux (Ubuntu/Debian):
#   Налаштувати pam_faillock і явно задати в /etc/security/faillock.conf,
#   наприклад:
#        deny = 5
#        unlock_time = 900
#   PAM-файли відрізняються між версіями дистрибутива, тому користуйтеся його
#   документацією або pam-auth-update. Перед змінами зробити резервні копії
#   /etc/pam.d і залишити відкритою root-консоль: неправильний PAM-конфіг може
#   заблокувати всіх користувачів.
#
# Linux (Fedora/RHEL):
#   У системах з authselect зазвичай використовують:
#        sudo authselect enable-feature with-faillock
#        sudo authselect apply-changes
#   Значення deny та unlock_time задаються в /etc/security/faillock.conf.
#
# macOS:
#   Політику невдалих входів рекомендовано задавати через MDM/configuration
#   profile. SKIP означає, що pwpolicy не повернула maxFailedLoginAttempts;
#   не слід вважати це підтвердженням наявності блокування.
#
# WSL:
#   PAM-політика працює лише для способів входу, які проходять через PAM у
#   Linux-дистрибутиві. Вона не блокує Windows-акаунт; його політика задається
#   окремо у Windows Account Lockout Policy.

check_lockout_linux() {
    local pam_text=""
    local value=""
    local file
    local -a pam_files=()

    for file in /etc/pam.d/common-auth /etc/pam.d/system-auth \
        /etc/pam.d/password-auth; do
        [[ -r "$file" ]] && pam_files+=("$file")
    done

    if (( ${#pam_files[@]} == 0 )); then
        result SKIP "Блокування облікового запису" "PAM-конфігурація недоступна" \
            "$(lockout_recommendation)"
        return
    fi

    pam_text=$(cat "${pam_files[@]}" 2>/dev/null || true)
    if ! printf '%s\n' "$pam_text" | \
        grep -Eq '^[[:space:]]*auth.*pam_(faillock|tally2)\.so'; then
        result FAIL "Блокування облікового запису" \
            "pam_faillock/pam_tally2 не налаштовано" "$(lockout_recommendation)"
        return
    fi

    # Спочатку шукаємо deny=N у PAM, потім — у faillock.conf.
    value=$(printf '%s\n' "$pam_text" | \
        grep -Eo 'deny[[:space:]]*=[[:space:]]*[0-9]+' | \
        tail -1 | tr -cd '0-9' || true)

    if [[ -z "$value" && -r /etc/security/faillock.conf ]]; then
        value=$(awk -F= '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*deny[[:space:]]*=/ {
                gsub(/[[:space:]]/, "", $2)
                last=$2
            }
            END { print last }
        ' /etc/security/faillock.conf)
    fi

    if [[ "$value" =~ ^[0-9]+$ ]] && (( value > 0 )); then
        result PASS "Блокування облікового запису" "після $value невдалих спроб"
    else
        result FAIL "Блокування облікового запису" "deny=N не задано явно" \
            "$(lockout_recommendation)"
    fi
}

check_lockout_macos() {
    local policy=""
    local value=""

    if have pwpolicy; then
        policy=$(pwpolicy -getglobalpolicy 2>/dev/null || true)
        value=$(printf '%s\n' "$policy" | \
            grep -Eo 'maxFailedLoginAttempts=[0-9]+' | tail -1 | cut -d= -f2 || true)
    fi

    if [[ "$value" =~ ^[0-9]+$ ]] && (( value > 0 )); then
        result PASS "Блокування облікового запису" "після $value невдалих спроб"
    else
        result SKIP "Блокування облікового запису" \
            "macOS не показала maxFailedLoginAttempts" "$(lockout_recommendation)"
    fi
}

check_account_lockout() {
    section "5. Блокування після невдалих входів"
    if [[ "$PLATFORM" == "macos" ]]; then
        check_lockout_macos
    else
        check_lockout_linux
    fi
}

# --- Підсумок ------------------------------------------------------------

print_summary() {
    local total=$((pass_count + fail_count + skip_count))
    local i
    local state
    local color

    section "Підсумок"
    printf '  Перевірок: %s | %sPASS: %s%s | %sFAIL: %s%s | %sSKIP: %s%s\n' \
        "$total" "$GREEN" "$pass_count" "$RESET" "$RED" "$fail_count" \
        "$RESET" "$YELLOW" "$skip_count" "$RESET"

    printf '\n  %sСписок перевірок:%s\n' "$BOLD" "$RESET"
    for i in "${!check_statuses[@]}"; do
        state="${check_statuses[$i]}"
        case "$state" in
            PASS) color="$GREEN" ;;
            FAIL) color="$RED" ;;
            SKIP) color="$YELLOW" ;;
            *)    color="" ;;
        esac
        printf '    %s[%s]%s %s\n' \
            "$color" "$state" "$RESET" "${check_labels[$i]}"
    done

    printf '\n'
    if (( fail_count > 0 )); then
        printf '  %sЄ налаштування, які не відповідають checklist.%s\n' "$RED" "$RESET"
    elif (( skip_count > 0 )); then
        printf '  %sКритичних невідповідностей не знайдено, але є неперевірені пункти.%s\n' \
            "$YELLOW" "$RESET"
    else
        printf '  %sУсі пункти checklist пройдено.%s\n' "$GREEN" "$RESET"
    fi

    printf '\n  %sПримітка:%s Це не офіційний CIS Benchmark і не замінює повний аудит безпеки.\n' \
        "$BOLD" "$RESET"
}

main() {
    detect_platform

    printf '%s%sСпрощений CIS checklist%s\n' "$BOLD" "$BLUE" "$RESET"
    printf 'Хост       : %s\n' "$(hostname)"
    printf 'Користувач : %s (uid=%s)\n' "$(id -un)" "$(id -u)"
    printf 'Платформа  : %s\n' "$PLATFORM_NAME"
    printf 'Дата       : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"

    check_password_length
    check_firewall
    check_ssh_root_login
    check_automatic_updates
    check_account_lockout
    print_summary

    if (( fail_count > 0 )); then
        return 1
    fi
    return 0
}

main "$@"
