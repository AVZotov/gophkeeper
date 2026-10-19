# GophKeeper

Клиент-серверный менеджер паролей: хранит логины и пароли, текст, файлы и
данные банковских карт. Данные шифруются на клиенте, сервер видит только
шифротекст. Выпускной проект курса Яндекс Практикума «Продвинутый Go».

- Требования: [docs/technical-spec.md](docs/technical-spec.md)
- Архитектурные решения: [docs/decisions.md](docs/decisions.md)

Проект в разработке: пока есть только каркас клиента и сервера.

## Требования

- Go — версия из директивы `toolchain` в [go.mod](go.mod): при более старом
  Go нужный тулчейн скачается автоматически
- [Task](https://taskfile.dev)
- protoc (libprotoc 36.2) — только для перегенерации кода из `.proto`

## Сборка

Сгенерированный код (`*.pb.go`) лежит в репозитории, для сборки protoc не
нужен.

```bash
task tools       # плагины protoc в версиях из go.mod
task proto       # перегенерация *.pb.go (сам ставит плагины, проверяет версию protoc)
task build       # bin/gophkeeper и bin/server
task build:all   # клиент под Windows, Linux, macOS × amd64, arm64 в bin/<os>-<arch>/
task check       # сборка, go vet, gofmt, тесты
task cover       # покрытие без сгенерированного кода
```

Контракт клиента и сервера — [api/gophkeeper/v1/gophkeeper.proto](api/gophkeeper/v1/gophkeeper.proto).

Версия берётся из `git describe --tags --always --dirty`, дата сборки — UTC
в формате ISO 8601. Обе подставляются в клиент через `-ldflags -X`.

## Клиент

```bash
$ bin/gophkeeper version
version:    v0.1.0
build date: 2026-10-19T10:00:00Z
```

Без `-ldflags` (например, `go run`) выводится `dev` и `unknown`.
