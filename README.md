
Команды для сборки, запуска и проверки через objdump

bash
# Сборка и запуск без оптимизации (-O0)
g++ -O0 -g -Wall -Wextra l2.cpp -o test_OA 
./test_OA

# Сборка и запуск с оптимизацией (-O2)
g++ -O2 -g -Wall -Wextra l2.cpp -o test_O2 
./test_O2

# Дизассемблирование Сценария B на -O2 (проверка удаления ветки if)
objdump -d -M intel test_O2 | grep -A 15 "<_Z10scenario_Bv>:"


/test_OA
=== Сценарий A (volatile на всём протяжении) ===
res = 0 | b is 0

=== Сценарий B (чтение из volatile в обычную переменную) ===
res = 0 | b is 0

[user@fedora ~]$ 
[user@fedora ~]$ 
[user@fedora ~]$ ./test_O2
=== Сценарий A (volatile на всём протяжении) ===
res = 0 | b is 0

=== Сценарий B (чтение из volatile в обычную переменную) ===
res = 0 | b is 0

[user@fedora ~]$
