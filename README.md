# Net Analyzer — Monitor de red en C++23

Herramienta CLI de análisis de red en **C++23** que lee estadísticas de interfaces de red y conexiones TCP directamente desde `/proc/net/`. Compatible con salida en tabla o JSON, monitorización en tiempo real de ancho de banda y filtrado por interfaz.

## Features

- ✅ **Estadísticas de interfaz**: RX/TX bytes, paquetes, errores y descartes desde `/proc/net/dev`
- ✅ **Conexiones TCP activas**: lectura de `/proc/net/tcp` y `/proc/net/tcp6` con detección de proceso asociado
- ✅ **Monitorización en tiempo real**: modo `--monitor` con refresco periódico y cálculo de ancho de banda
- ✅ **Salida estructurada JSON**: integrable con scripts y herramientas externas
- ✅ **Filtrado por interfaz**: limita la salida a una interfaz específica con `--filter`
- ✅ **Arquitectura RAII**: `NetAnalyzer` con manejo de errores mediante `std::expected`
- ✅ **C++23 moderno**: concepts, ranges, string_view, std::println, std::format
- ✅ **Logging**: spdlog estructurado
- ✅ **Tests**: Catch2 v3 con unitarios, integración y benchmarks

## Stack tecnológico

| Componente   | Tecnología                        |
|--------------|------------------------------------|
| Lenguaje     | C++23 (GCC 14)                    |
| Build        | CMake 3.28+ / Ninja               |
| Argumentos   | CLI11 (FetchContent)              |
| JSON         | nlohmann-json (FetchContent)      |
| Logging      | spdlog (FetchContent)             |
| Tests        | Catch2 v3 (FetchContent)          |
| APIs Linux   | /proc/net/dev, /proc/net/tcp, /proc/net/tcp6 |
| Contenedor   | Docker multi-stage (gcc:14)       |

## Requisitos

- **Compiler**: GCC 14+ (C++23 completo: std::expected, std::println)
- **CMake**: ≥ 3.28
- **Ninja**: recomendado
- **Sistema**: Linux (lee /proc/net)

## Compilación

```bash
# Usando CMake presets (recomendado)
cmake --preset debug
cmake --build --preset debug

# O manualmente
cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Ejecutar tests
ctest --preset debug
```

## Uso

```bash
# Mostrar estadísticas de interfaces
./build/debug/net-analyzer

# Mostrar conexiones TCP activas
./build/debug/net-analyzer --connections

# Modo monitor en tiempo real
./build/debug/net-analyzer --monitor

# Salida JSON
./build/debug/net-analyzer --json

# Filtrar por interfaz
./build/debug/net-analyzer --filter eth0

# Monitor cada 5 segundos
./build/debug/net-analyzer --monitor --interval 5

# Monitor en JSON con filtro
./build/debug/net-analyzer --monitor --json --filter wlan0
```

## Docker

```bash
docker build -t net-analyzer .
docker run --rm --net=host net-analyzer
```

## API /proc

| Archivo            | Descripción                          |
|--------------------|--------------------------------------|
| `/proc/net/dev`    | Estadísticas de interfaces de red    |
| `/proc/net/tcp`    | Conexiones TCP IPv4 activas          |
| `/proc/net/tcp6`   | Conexiones TCP IPv6 activas          |
| `/proc/[pid]/fd/`  | Descriptores de archivo por proceso  |
