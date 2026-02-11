# Сборка инсталлятора (Windows)

## 1. Установка NSIS (для .exe инсталлятора)

Чтобы собирать установочный `.exe`, нужен **NSIS**:

- Скачать: **https://nsis.sourceforge.net/Download**
- Установить и добавить в **PATH** папку с `makensis.exe`.  
  Если NSIS не установлен, можно собрать только ZIP (см. ниже).

## 2. Команды сборки инсталляционного файла

Выполнять из **корня проекта** (каталог с `CMakeLists.txt`).

### Шаг 1. Настройка (один раз или после смены CMakeLists)

Если меняли путь установки или другие настройки CPack, а инсталлятор ведёт себя по-старому — **очистите кэш** и настройте заново:

```powershell
Remove-Item -Recurse -Force build
cmake -B build -G "Visual Studio 17 2022" -A x64
```

Иначе достаточно:

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
```

### Шаг 2. Сборка Release

```powershell
cmake --build build --config Release
```

### Шаг 3. Создание пакетов (инсталлятор + ZIP)

```powershell
cd build
cpack -C Release
cd ..
```

Либо одной строкой из корня:

```powershell
cmake --build build --config Release; cd build; cpack -C Release; cd ..

or

cmake --build build --config Release && cd build && cpack -C Release && cd ..
```

### Результат

В каталоге `build/` появятся:

- **token-signer-0.1.1-win64.exe** — инсталлятор NSIS (устанавливает в `C:\Program Files\ArtopiasLab\token-signer 0.1.1`);
- **token-signer-0.1.1-win64.zip** — архив для ручной распаковки.

### Только ZIP (без NSIS)

```powershell
cd build
cpack -G ZIP -C Release
cd ..
```
