#!/usr/bin/env bash
#
# net_diag.sh — read-only діагностика мережі для Linux, macOS та WSL.
#
# Запуск:
#   chmod +x net_diag.sh
#   ./net_diag.sh
#
# Код повернення: 0 — усі перевірки OK, 1 — є хоча б один FAIL.



set -euo pipefail
#   -e        — завершити роботу після необробленої помилки команди;
#   -u        — вважати звернення до неоголошеної змінної помилкою;
#   pipefail  — не приховувати помилку команди всередині конвеєра.
# Команди, невдача яких є нормальною частиною діагностики, нижче запускаються
# всередині if або мають `|| true`, тому скрипт збере звіт до кінця.

# Кольори вмикаємо лише для інтерактивного термінала. NO_COLOR дає змогу
# вимкнути їх явно: NO_COLOR=1 ./net_diag.sh
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    BLUE=$'\033[34m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED=""
    GREEN=""
    BLUE=""
    BOLD=""
    RESET=""
fi

# Глобальні лічильники потрібні для фінального підсумку та коду повернення.
ok_count=0
fail_count=0

# Перевіряє, чи встановлена команда. Увесь службовий вивід приховується.
# Приклад: `have curl` повертає успіх, якщо curl доступний через PATH.
have() {
    command -v "$1" >/dev/null 2>&1
}

# Друкує заголовок розділу в одному стилі.
section() {
    printf '\n%s%s%s\n' "$BOLD$BLUE" "$1" "$RESET"
}

# Друкує результат перевірки та оновлює відповідний лічильник.
# Аргументи: статус (OK/FAIL), назва перевірки, необов'язкова подробиця.
status() {
    local state="$1"
    local label="$2"
    local detail="${3:-}"

    if [[ "$state" == "OK" ]]; then
        ok_count=$((ok_count + 1))
        printf '  %s[ OK ]%s %s' "$GREEN" "$RESET" "$label"
    else
        fail_count=$((fail_count + 1))
        printf '  %s[FAIL]%s %s' "$RED" "$RESET" "$label"
    fi

    if [[ -n "$detail" ]]; then
        printf ' — %s' "$detail"
    fi
    printf '\n'
}

# Додає однаковий відступ до кожного рядка багаторядкового результату команди.
print_block() {
    local text="$1"

    while IFS= read -r line; do
        printf '         %s\n' "$line"
    done <<< "$text"
}

# uname відрізняє macOS від Linux, але WSL теж повертає "Linux".
# Тому для WSL додатково шукаємо слово Microsoft у даних ядра.
detect_platform() {
    case "$(uname -s)" in
        Linux*)
            if grep -qi microsoft /proc/version 2>/dev/null ||
                grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
                PLATFORM="wsl"
                PLATFORM_NAME="WSL (Windows Subsystem for Linux)"
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
            printf '%sНепідтримувана платформа: %s%s\n' \
                "$RED" "$(uname -s)" "$RESET" >&2
            exit 1
            ;;
    esac
}

check_interfaces() {
    local output=""

    section "1. Мережеві інтерфейси та IP-адреси"

    if [[ "$PLATFORM" == "macos" ]]; then
        if have ifconfig; then
            # У macOS команда `ip` зазвичай відсутня. З повного виводу ifconfig
            # awk залишає активні інтерфейси та їхні IPv4/IPv6-адреси.
            # Локальні IPv6-адреси fe80:: пропускаємо, щоб звіт був коротшим.
            output=$(ifconfig -a | awk '
                /^[[:alnum:]][[:alnum:]_.-]*:/ { iface=$1; sub(/:$/, "", iface) }
                /status: active/ { active[iface]=1 }
                /inet / { addresses[iface]=addresses[iface] " IPv4=" $2 }
                /inet6 / && $2 !~ /^fe80:/ { addresses[iface]=addresses[iface] " IPv6=" $2 }
                END {
                    for (name in active) {
                        printf "%-12s%s\n", name, (addresses[name] ? addresses[name] : " IP не призначено")
                    }
                }
            ')
        fi
    else
        # `ip` — сучасний стандарт Linux і WSL. Якщо його немає (наприклад,
        # у мінімальному образі), використовуємо старішу команду ifconfig.
        if have ip; then
            output=$(ip -brief address show 2>/dev/null || true)
        elif have ifconfig; then
            output=$(ifconfig -a 2>/dev/null || true)
        fi
    fi

    if [[ -n "$output" ]]; then
        status OK "Інтерфейси знайдено"
        print_block "$output"
    else
        status FAIL "Не вдалося отримати інтерфейси" "потрібна команда ip або ifconfig"
    fi
}

check_gateway() {
    local output=""

    section "2. Шлюз за замовчуванням"

    if [[ "$PLATFORM" == "macos" ]]; then
        # route показує фактичний маршрут за замовчуванням у macOS.
        # netstat — резервний варіант для середовищ без route.
        if have route; then
            output=$(route -n get default 2>/dev/null | awk '/gateway:|interface:/ { print $1, $2 }' || true)
        fi
        if [[ -z "$output" ]] && have netstat; then
            output=$(netstat -rn -f inet 2>/dev/null | awk '$1 == "default" { print "gateway:", $2, "interface:", $NF; exit }' || true)
        fi
    else
        # У Linux/WSL шукаємо рядок `default` у таблиці маршрутів.
        # Класична route -n потрібна як сумісний запасний варіант.
        if have ip; then
            output=$(ip route show default 2>/dev/null || true)
        fi
        if [[ -z "$output" ]] && have route; then
            output=$(route -n 2>/dev/null | awk '$1 == "0.0.0.0" { print "gateway:", $2, "interface:", $8; exit }' || true)
        fi
    fi

    if [[ -n "$output" ]]; then
        status OK "Шлюз налаштовано"
        print_block "$output"
    else
        status FAIL "Шлюз не знайдено" "немає маршруту за замовчуванням"
    fi
}

check_dns() {
    local output=""

    section "3. DNS-сервери"

    if [[ "$PLATFORM" == "macos" ]] && have scutil; then
        # scutil враховує DNS усіх мережевих сервісів macOS. Масив seen в awk
        # прибирає дублікати адрес зі звіту.
        output=$(scutil --dns 2>/dev/null | awk '
            /nameserver\[[0-9]+\]/ && !seen[$3]++ { print $3 }
        ' || true)
    elif have resolvectl; then
        # На Linux із systemd-resolved актуальні сервери показує resolvectl.
        output=$(resolvectl dns 2>/dev/null || true)
    fi

    # /etc/resolv.conf працює як універсальний резервний варіант, зокрема у WSL.
    if [[ -z "$output" && -r /etc/resolv.conf ]]; then
        output=$(awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf)
    fi

    if [[ -n "$output" ]]; then
        status OK "DNS-сервери знайдено"
        print_block "$output"
    else
        status FAIL "DNS-сервери не знайдено" "перевірте системні мережеві налаштування"
    fi
}

check_internet() {
    # Значення 0 означатиме успішний ping. Починаємо з 1 (перевірка не пройдена).
    local ping_ok=1
    local internet_ok=1
    local connection_detail=""
    local external_ip=""

    section "4. Доступ до інтернету"

    # Спочатку робимо лише HEAD-запит із тайм-аутом 5 секунд: він перевіряє
    # маршрут, DNS і HTTPS, але не завантажує тіло вебсторінки.
    # HTTPS — краща практична перевірка, бо ICMP часто блокує файрвол.
    if have curl && curl --fail --silent --show-error --head \
        --max-time 5 https://example.com/ >/dev/null 2>&1; then
        internet_ok=0
        connection_detail="HTTPS-запит до example.com успішний"
    fi

    # Якщо curl відсутній або HTTPS не спрацював, перевіряємо відому IP-адресу
    # Cloudflare. Параметр -W має різні одиниці: мілісекунди в macOS і секунди
    # в Linux, тому команди для платформ розділені.
    if (( internet_ok != 0 )) && have ping; then
        if [[ "$PLATFORM" == "macos" ]]; then
            if ping -c 1 -W 3000 1.1.1.1 >/dev/null 2>&1; then
                ping_ok=0
            fi
        elif ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1; then
            ping_ok=0
        fi
    fi

    if (( ping_ok == 0 )); then
        internet_ok=0
        connection_detail="1.1.1.1 відповідає на ping; HTTPS недоступний"
    fi

    if (( internet_ok != 0 )); then
        status FAIL "Інтернет недоступний" "не вдалися HTTPS і ping до 1.1.1.1"
        status FAIL "Зовнішню IP-адресу не визначено" "немає доступу до інтернету"
        return
    fi

    status OK "Інтернет доступний" "$connection_detail"

    # Зовнішню адресу не можна дізнатися лише з локальних налаштувань, тому
    # звертаємося до api64.ipify.org. Сервіс повертає IPv4 або IPv6 простим
    # текстом. Тайм-аут не дозволяє цій додатковій перевірці затримати звіт.
    if ! have curl; then
        status FAIL "Зовнішню IP-адресу не визначено" "команда curl не встановлена"
        return
    fi

    external_ip=$(curl --fail --silent --max-time 5 \
        https://api64.ipify.org 2>/dev/null || true)

    if [[ -n "$external_ip" ]]; then
        status OK "Зовнішню IP-адресу визначено" "$external_ip"
    else
        status FAIL "Зовнішню IP-адресу не визначено" "сервіс api64.ipify.org недоступний"
    fi
}

check_ports() {
    local output=""
    local tool=""

    section "5. Локальні порти, що прослуховуються"

    if [[ "$PLATFORM" == "macos" ]]; then
        # lsof показує процес, PID і локальну TCP-адресу. Без sudo буде видно
        # не все, але для звичайної діагностики цього достатньо.
        if have lsof; then
            output=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || true)
            tool="lsof"
        elif have netstat; then
            output=$(netstat -an 2>/dev/null | awk '/LISTEN|^udp/ { print }' || true)
            tool="netstat"
        fi
    else
        # Прапорці ss/netstat: -l — лише listening, -n — без DNS-перетворення,
        # -t — TCP, -u — UDP. Не додаємо процеси, щоб не вимагати sudo.
        if have ss; then
            output=$(ss -lntu 2>/dev/null || true)
            tool="ss"
        elif have netstat; then
            output=$(netstat -lntu 2>/dev/null || true)
            tool="netstat"
        elif have lsof; then
            output=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || true)
            tool="lsof"
        fi
    fi

    if [[ -n "$output" ]]; then
        status OK "Список портів отримано" "$tool"
        print_block "$output"
    elif [[ -n "$tool" ]]; then
        status OK "Портів, що прослуховуються, не знайдено" "$tool"
    else
        status FAIL "Не вдалося перевірити порти" "потрібна команда ss, lsof або netstat"
    fi
}

print_summary() {
    # Загальна кількість має дорівнювати сумі успішних і невдалих перевірок.
    local total=$((ok_count + fail_count))

    section "Підсумок"
    printf '  Перевірок: %s | %sOK: %s%s | %sFAIL: %s%s\n' \
        "$total" "$GREEN" "$ok_count" "$RESET" "$RED" "$fail_count" "$RESET"

    if (( fail_count == 0 )); then
        printf "  %sУсі обов'язкові перевірки пройдено.%s\n" "$GREEN" "$RESET"
    else
        printf '  %sЄ проблеми, які потребують уваги.%s\n' "$RED" "$RESET"
    fi
}

main() {
    # Платформу визначаємо першою, бо від неї залежать команди всіх розділів.
    detect_platform

    printf '%s%sДіагностика мережі%s\n' "$BOLD" "$BLUE" "$RESET"
    printf 'Хост      : %s\n' "$(hostname)"
    printf 'Платформа : %s\n' "$PLATFORM_NAME"
    printf 'Дата      : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"

    # Кожна функція відповідає за одну обов'язкову частину домашнього завдання.
    check_interfaces
    check_gateway
    check_dns
    check_internet
    check_ports
    print_summary

    # Ненульовий код дає змогу використовувати скрипт в автоматизації:
    # інший скрипт або CI одразу побачить, що діагностика знайшла проблему.
    if (( fail_count > 0 )); then
        return 1
    fi
    return 0
}

# Передаємо всі аргументи main. Зараз аргументів немає, але такий шаблон
# дозволяє безпечно додати їх у майбутньому.
main "$@"
