// Защита от повторного определения макроса (g++ на Linux часто определяет _GNU_SOURCE сам).
// Макрос открывает доступ к константам регистров x86_64: REG_RIP, REG_RAX, REG_RDX.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// ============================================================================
// 1. ТАБЛИЦА ПАТТЕРНОВ ИНСТРУКЦИЙ DIV / IDIV (из дампов objdump -d)
// ============================================================================
struct DivPattern {
    const char* name;    // Имя паттерна для отладки
    uint8_t bytes;    // Эталонные байты опкода (макс. длина в таблице — 6 байт)
    uint8_t mask;     // Битовая маска: 0xFF — строгое совпадение, 0xF8 — игнорируем 3 бита регистра
    uint8_t len;         // Длина инструкции в байтах (величина сдвига RIP)
};

static const DivPattern kDivPatterns[] = {
    // 32-битное знаковое деление на регистр: F7 /7 (ModRM: 11 111 reg -> 0xF8..0xFF, напр. f7 f9 = idiv ecx)
    {"idiv reg32",        {0xF7, 0xF8, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0xF8, 0x00, 0x00, 0x00, 0x00}, 2},

    // 32-битное беззнаковое деление на регистр: F7 /6 (ModRM: 11 110 reg -> 0xF0..0xF7, напр. f7 f1 = div ecx)
    {"div reg32",         {0xF7, 0xF0, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0xF8, 0x00, 0x00, 0x00, 0x00}, 2},

    // 32-битное знаковое деление на расширенный регистр (r8d..r15d) с префиксом REX.B (0x41) — часто на -O2
    {"idiv ext_reg32",    {0x41, 0xF7, 0xF8, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x00}, 3},

    // 32-битное знаковое деление на локальную переменную в стеке через RBP: F7 7D <disp8> (типично для -O0)
    {"idiv [rbp+disp8]",  {0xF7, 0x7D, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}, 3},

    // 32-битное знаковое деление на переменную в стеке через RSP (с SIB-байтом 0x24): F7 7C 24 <disp8>
    {"idiv [rsp+disp8]",  {0xF7, 0x7C, 0x24, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00}, 4},

    // 32-битное знаковое деление на глобальную переменную (RIP-relative): F7 3D <disp32>
    {"idiv [rip+disp32]", {0xF7, 0x3D, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}, 6},

    // 64-битное знаковое деление на регистр (rax..rdi): префикс REX.W (0x48) + F7 + 0xF8..0xFF
    {"idiv reg64",        {0x48, 0xF7, 0xF8, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x00}, 3},

    // 64-битное знаковое деление на расширенный регистр (r8..r15): префикс REX.WB (0x49) + F7 + 0xF8..0xFF
    {"idiv ext_reg64",    {0x49, 0xF7, 0xF8, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x00}, 3}
};

// ============================================================================
// 2. СРАВНЕНИЕ БАЙТОВ ПО АДРЕСУ RIP С ТАБЛИЦЕЙ ПАТТЕРНОВ
// ============================================================================
static bool match_pattern(const uint8_t* code, const DivPattern& pat) {
    for (uint8_t i = 0; i < pat.len; ++i) {
        if ((code[i] & pat.mask[i]) != pat.bytes[i]) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// 3. ОБРАБОТЧИК СИГНАЛА SIGFPE (ЭМУЛЯЦИЯ ПОВЕДЕНИЯ ARM64)
// ============================================================================
static void sigfpe_handler(int sig, siginfo_t* info, void* ucontext_raw) {
    (void)sig;
    (void)info;

    // Извлекаем контекст процессора и массив регистров общего назначения
    ucontext_t* ctx = static_cast<ucontext_t*>(ucontext_raw);
    greg_t* gregs = ctx->uc_mcontext.gregs;

    // Извлекаем текущий адрес указателя инструкций RIP
    const uint8_t* rip = reinterpret_cast<const uint8_t*>(gregs[REG_RIP]);

    // Сравниваем машинные байты по адресу RIP с таблицей известных паттернов
    for (const auto& pat : kDivPatterns) {
        if (match_pattern(rip, pat)) {
            // Инструкция распознана — подменяем состояние CPU на ARM-style:
            gregs[REG_RAX] = 0;        // Записываем 0 в RAX (частное)
            gregs[REG_RDX] = 0;        // Записываем 0 в RDX (остаток)
            gregs[REG_RIP] += pat.len; // Продвигаем RIP на длину распознанной инструкции
            return;
        }
    }

    // Если инструкция не распознана — аварийно завершаем процесс (async-signal-safe)
    const char err_msg[] = "[FATAL] SIGFPE: unrecognized instruction at RIP, aborting.\n";
    ssize_t unused = write(STDERR_FILENO, err_msg, sizeof(err_msg) - 1);
    (void)unused;
    _exit(1);
}

// ============================================================================
// 4. НАСТРОЙКА ОБРАБОТЧИКА SIGFPE ЧЕРЕЗ SIGACTION С ФЛАГОМ SA_SIGINFO
// ============================================================================
static bool setup_sigfpe_handler() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));

    // Флаг SA_SIGINFO обязателен для передачи siginfo_t и ucontext_t в обработчик
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigfpe_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGFPE, &sa, nullptr) == -1) {
        perror("sigaction(SIGFPE) failed");
        return false;
    }
    return true;
}

// ============================================================================
// 5. ТЕСТОВЫЕ СЦЕНАРИИ A И B
// ============================================================================

// Сценарий A: переменная-делитель объявлена как volatile на всём протяжении.
// Компилятор обязан перечитывать её из памяти и перед делением, и при проверке if (b == 0).
__attribute__((noinline))
void scenario_A() {
    printf("=== Сценарий A (volatile на всём протяжении) ===\n");
    int a = 100;
    volatile int b = 0;

    int res = a / b; // Генерируется idiv; срабатывает SIGFPE -> обработчик возвращает res = 0

    if (b == 0) {
        printf("res = %d | b is 0\n\n", res);
    } else {
        printf("res = %d | b is NOT 0\n\n", res);
    }
}

// Сценарий B: значение 0 читается из volatile-переменной в обычную локальную переменную b.
// После деления (a / b) на -O2 оптимизатор считает, что b != 0 (иначе было бы UB),
// и вырезает ветку if (b == 0) из скомпилированного кода.
__attribute__((noinline))
void scenario_B() {
    printf("=== Сценарий B (чтение из volatile в обычную переменную) ===\n");
    int a = 100;
    volatile int v_zero = 0;
    int b = v_zero;

    int res = a / b; // Генерируется idiv; срабатывает SIGFPE -> обработчик возвращает res = 0

    if (b == 0) {
        printf("res = %d | b is 0\n\n", res);
    } else {
        printf("res = %d | b is NOT 0\n\n", res);
    }
}

int main() {
    if (!setup_sigfpe_handler()) {
        return 1;
    }

    scenario_A();
    scenario_B();

    return 0;
}
Используйте код с осторожностью.

Команды для сборки, запуска и проверки через objdump

bash
# Сборка и запуск без оптимизации (-O0)
g++ -O0 -g -Wall -Wextra l2.cpp -o test_O0 && ./test_O0

# Сборка и запуск с оптимизацией (-O2)
g++ -O2 -g -Wall -Wextra l2.cpp -o test_O2 && ./test_O2

# Дизассемблирование Сценария B на -O2 (проверка удаления ветки if)
objdump -d -M intel test_O2 | grep -A 15 "<_Z10scenario_Bv>:"
Используйте код с осторожностью.
Запустите обе сборки и сверьте вывод test_O0 и test_O2 — если при выполнении test_O2 в scenario_B сгенерируется новый паттерн idiv, которого ещё нет в kDivPatterns, пришлите вывод objdump, и я дополню таблицу.
