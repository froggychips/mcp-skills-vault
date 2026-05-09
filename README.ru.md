# mcp-skills-vault

Скиллы для Claude Code для работы с экосистемой Model Context Protocol (MCP) — поиск MCP-серверов, оценка качества и безопасная установка.

> [!NOTE]
> Сделано для системы [скиллов Claude Code](https://claude.com/claude-code). Скопируй папку в `~/.claude/skills/` — Claude будет автоматически активировать скилл, когда запрос пользователя совпадёт с его описанием.

[English documentation →](./README.md)

## Что здесь есть

| Скилл | Назначение | Статус |
|---|---|---|
| [`mcp-ecosystem-intelligence/`](./mcp-ecosystem-intelligence) | Найти, оценить и установить MCP-серверы. База из **30 проверенных инструментов** и сканер безопасности цепочки поставок. | Готов |
| [`mcp-swift-synthesizer.skill`](./mcp-swift-synthesizer.skill) | Конвертация MCP-серверов в нативные Swift-бинарники — снижение RAM с 150–300 МБ до 1–10 МБ. | Концепт |

## Быстрая установка (Ecosystem Intelligence)

```bash
git clone https://github.com/froggychips/mcp-skills-vault.git
mkdir -p ~/.claude/skills
cp -r mcp-skills-vault/mcp-ecosystem-intelligence ~/.claude/skills/
```

После установки можно спросить Claude:

> _«Есть ли MCP-сервер для ClickHouse, который стоит добавить в проект?»_
> _«Проведи аудит моего MCP-окружения.»_
> _«Какие MCP-инструменты поставить для Next.js-приложения на Cloudflare?»_

Скилл активируется по совпадению с описанием. Он:

1. Читает манифесты проекта (`package.json`, `pyproject.toml`, …) для определения стека.
2. Сначала ищет в локальной `tools_database.json` (30 проверенных серверов, 14 категорий).
3. При отсутствии в кэше — `registry.modelcontextprotocol.io` → агрегаторы → `gh search`.
4. Считает Health Score через [`scripts/calculate_health.cjs`](./mcp-ecosystem-intelligence/scripts/calculate_health.cjs).
5. **Проверяет** кандидатов: хэш целостности, URL репозитория, install-хуки, CVE.
6. Рекомендует лучший вариант в каждой категории с готовой командой установки.
7. С согласия пользователя **сканирует и устанавливает** — напрямую редактирует `~/.claude.json` (не через `claude mcp add`, который печатает bearer-токен в stdout).

## Безопасность

Каждый npm-пакет проходит проверку через [`scripts/verify_integrity.cjs`](./mcp-ecosystem-intelligence/scripts/verify_integrity.cjs) перед установкой.

```bash
node mcp-ecosystem-intelligence/scripts/verify_integrity.cjs
```

| Проверка | Что ловит |
|---|---|
| **Хэш целостности** | Подмена тарбола — sha512 скачанного пакета должен совпадать с сохранённым |
| **URL репозитория** | Перехват имени пакета — `npm repository.url` должен совпадать с `source_url` в базе |
| **Install-хуки** | Скрипты `preinstall`/`postinstall`, выполняющие произвольный код при `npx -y` |
| **CVE-советники** | Известные уязвимости через npm advisory bulk API (без внешних зависимостей) |
| **socket.dev** | Глубокий анализ цепочки поставок: обфускация, malware-сигнатуры (флаг `--socket`) |

Флаги:

| Флаг | Действие |
|---|---|
| `--update` | Обновить `version` + `pkg_integrity` из npm |
| `--strict` | Превратить WARN (хуки, отсутствующий repo) в hard-fail |
| `--socket` | Добавить сканирование через socket.dev |
| `--no-audit` | Пропустить advisory API (офлайн-режим) |

Все записи в `tools_database.json` содержат пинованные версии, sha512-хэши и поле `trust` (`"verified"` — для исходных 30 записей; `"candidate"` — для найденных в ходе discovery). Docker-установки используют `--cap-drop ALL --security-opt no-new-privileges`.

## Формула Health Score

```
score = min(20, 10·log10(stars+1))   # популярность, с потолком
      + {40|20|10|0}                  # свежесть: <30д / <90д / <180д / старше
      + 30 если в реестре
      + 15 если есть команда установки
      + 5  если open_issues/10 < 5
```

Тиры (максимум 110):

| Score | Тир | Поведение |
|---|---|---|
| 85+ | Core | рекомендовать по умолчанию |
| 65–84 | Recommended | рекомендовать с примечанием |
| 40–64 | Experimental | упоминать только по запросу |
| < 40 | Deprecated | скрывать, если не спросят |

## База инструментов

`mcp-ecosystem-intelligence/assets/tools_database.json` — **30 записей** в 14 категориях:

```
browser  database  demo  docs   filesystem  http   infra
memory   meta      observability  payments  pm    reasoning
search   utility   vcs   web-scraping
```

Распределение: **18 Core / 10 Recommended / 2 Experimental**.

Включает семь официальных серверов `modelcontextprotocol/servers` (filesystem, fetch, git, memory, sequentialthinking, time, everything), серверы от вендоров (`github`, `microsoft/playwright`, `cloudflare`, `notion`, `sentry`, `stripe`, `neon`, `mongodb`, `redis`, `clickhouse`, `awslabs/mcp`, `context7`, …) и качественные community-проекты (`mcp-atlassian`, `firecrawl`, `tavily`, `exa`, `brave`, `kubernetes`, `duckduckgo`, …).

Схема каждой записи:

```jsonc
{
  "name": "pkg-name",
  "category": "database|search|infra|…",
  "install_cmd": "npx -y pkg@1.2.3",   // всегда с пинованной версией
  "source_url": "https://github.com/owner/repo",
  "version": "1.2.3",                  // пинованная npm-версия
  "pkg_integrity": "sha512-…",         // npm dist.integrity (sha512 тарбола)
  "trust": "verified",                 // "verified" | "candidate"
  "health_score": 105.0,
  "classification": "Core"
}
```

## Обёртка CLI/API как MCP

Если discovery и scoring не нашли ничего подходящего, скилл генерирует минимальную обёртку из шаблона `mcp-ecosystem-intelligence/assets/mcp-wrapper-template/`:

```
mcp-wrapper-template/
  server.js       # @modelcontextprotocol/sdk + StdioServerTransport boilerplate
  package.json    # пинованная мажорная версия SDK, node>=18, MIT
```

Замени плейсхолдеры `{{name}}` и `{{tool}}`, добавь определения инструментов в обработчик `ListTools`, положи результат в `~/.claude/skills/<your-tool>-mcp/` или опубликуй на npm.

## Теги

`claude-code` · `claude-skill` · `mcp` · `model-context-protocol` · `mcp-server` · `mcp-tools` · `anthropic` · `ai-agents`

## Лицензия

[MIT](./LICENSE)
