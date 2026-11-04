---
name: host-privacy-sweep
description: "Find private/sensitive things sitting on a machine: leaked tokens and keys in files, ssh keys, messenger/CLI session files, committed or dropped databases, .env files, shell histories with creds, config credentials. Runs locally or over the network via ssh (own or administered machines; client hosts only under ROE). Parallel per-host scanner subagents, redacted inventory, cleanup plan. Use when: найти приватные штуки на машине, что у меня на компе утекло, найти секреты на маке/ноуте/сервере, host secrets sweep, scan my machine for secrets/tokens/keys, инвентаризация секретов перед продажей машины, почистить машину от кредов."
metadata:
  short-description: Machine secrets sweep — local and over ssh
---

# Host Privacy Sweep — приватные штуки на машине

Инвентаризация чувствительного на одной машине или парке: утёкшие в файлы
токены и ключи, ssh-ключи, сессии мессенджеров/CLI, sqlite-базы с токенами,
`.env`, shell-истории с кредами, конфиги с паролями. Читай и фиксируй —
ничего не удаляй и не перемещай сам. Вывод всегда редактированный:
first4…last4 + sha256-12, полные значения не покидают машину.

## Порог входа

1. **Свои машины** — владелец и есть заказчик, можно сразу. Любой хост,
   резолвящийся по ssh: ноутбуки, десктопы, серверы, VPS.
2. **Хост клиента** — только по ROE/авторизации, пробы read-only, артефакты
   masked в рабочей папке клиентского прогона.
3. Чужая машина без авторизации — стоп. Это не пассивная разведка.
4. Прогон фиксируется тикетом в трекере команды; для клиентских машин —
   полный канон клиентской работы (авторизация, scope, отчёт).

## Движок

The bundled sweep script (файл `secret-sweep.sh`, идёт в комплекте со
скиллом). Локально:

```sh
scripts/secret-sweep.sh --root ~ --mode all --git-history > sweep.jsonl
```

По сети — скрипт не нужно ставить на удалённую машину, он стримится на
ssh-хост как stdin (args после `--` уходят скрипту):

```sh
ssh -o BatchMode=yes <host> 'bash -s' -- --root ~ --mode all < scripts/secret-sweep.sh > <host>.jsonl
# git-history удалённо: сначала скопировать скрипт (нужен git в PATH хоста)
scp -o BatchMode=yes scripts/secret-sweep.sh <host>:/tmp/ && \
  ssh -o BatchMode=yes <host> '/tmp/secret-sweep.sh --root ~ --mode all --git-history' > <host>.jsonl
```

`--exclude <dirname>` добавляет prune (по умолчанию уже выкинуты
node_modules, .venv, __pycache__, .cache, Caches, .Trash, .git/objects).
`--max-mb` — потолок файла для text-режима. Режимы: text / names /
binary / all. Выход JSONL; exit 1 = есть находки.

## Фазы

1. **Разведка хостов (главный агент).** Список машин, проверка ssh
   (`ssh -o BatchMode=yes <host> 'echo ok'` — не прошёл: хост в пропущенные
   с причиной, без фолбэков). Для каждой: ОС, наличие rg/git/sqlite3
   (`command -v …`) — влияет на слой движка, не блокирует (fallback есть).
2. **Фанаут (параллельные субагенты).** Один агент — одна машина, одним
   сообщением. Если в среде определён профильный субагент-сканер — он;
   иначе general-purpose со скелетом:

```
Ты — sweeper приватных данных на машине <host> (ОС <os>).
Доступ: ssh -o BatchMode=yes <host> '<cmd>' (или локально, если host=local).
Ничего не менять, не удалять, не перемещать. Полные значения секретов
не выводить и не записывать — только masked (first4..last4 + sha256-12).
1. Сними JSONL движком (команды выше). Если rg нет — движок сам упадёт на grep.
2. Добавь поверхности сверх движка, по ОС:
   - все: ~/.ssh/config (Host/HostName/User — хосты не секретны, IdentityFile
     пути), crontab -l, env | grep -iE 'token|key|secret|pass' (только имена
     переменных! значения — masked), ~/.config/* credentials, docker config.json
   - macOS: ~/Library/Application Support — имена подпапок мессенджеров
     (Telegram tdata, session-файлы), Keychain НЕ трогаем (защищён),
     но наличие ключей в файлах рядом фиксируем
   - Linux: ~/.config/gcloud, ~/.kube, ~/.aws, systemd user units с Environment=
3. Триаж: каждой находке статус real|test|doc, приоритет high|candidate.
4. Итог в <workdir>/<host>.md: таблица (kind/prio/path/line/masked/sha/статус),
   счётчики, «чистые» поверхности. Верни счётчики + топ-5 опасных (masked).
```

3. **Сводка и план (главный агент).** Парк машин: кросс-хост дедуп по sha
   (один ключ на N машинах = одна находка, важнее). Итог:
   `output/host-sweep-<date>/summary.md` (для клиента — в рабочей папке
   клиентского прогона):
   - инвентарь по машинам (counts по kind/prio)
   - топ-угрозы: валидные прод-токены в мусорных файлах, чужие ssh-ключи,
     session-файлы в незащищённых местах, БД с токенами
   - **план очистки:** ротировать (живые токены) → зашифровать/переместить
     (ключи в ~/.ssh с правами, keychain) → удалить (мусор с кредами,
     старые .env) → prevention (pre-commit, gitignore, секреты в
     менеджер). Исполнение плана — отдельный шаг с явного согласия
     владельца, не в этом прогоне.

## Гигиена

- Read-only и masked — на всех слоях (см. выше): find/strings/sqlite3
  .tables только читают, свип ничего не мутирует; дедуп находок по
  sha256, отчёты читаются только в masked-виде.
- Живые проверки токенов у провайдеров — отдельная авторизованная
  дорожка по ROE, в этот свип не входит.
- Большие домашние директории: сначала `--mode names` (быстро, имена),
  потом text/binary по зонам. Не гнать всё сразу на 500 ГБ home.
- Evidence: JSONL-файлы остаются в workdir прогона; наружу (публичный
  репо, база знаний) — только summary с masked-находками.
