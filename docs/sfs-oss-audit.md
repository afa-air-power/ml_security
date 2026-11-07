# Сверка с открытыми сканерами

Проверен конкурсный архив `Задание_SFS.tar`, 7 ноября 2026. Исходники, модель и содержимое сериализованных объектов не запускались. [Офлайн-триаж проекта](sfs-triage.md) · [Сравнение в JSON](sfs-oss-audit.json)

| Инструмент | Область | Результат |
| --- | --- | --- |
| [Bandit 1.9.4](https://bandit.readthedocs.io/en/latest/) | `src/`, `model/_fixtures/`, `seed_cache.py`; все встроенные правила, игнорирование `nosec` | 18 сигналов. Нашёл SQL и shell, а также подсветил общий временный путь, запуск через PATH и открытый bind. |
| [Semgrep CE 1.183.0](https://github.com/semgrep/semgrep), набор `p/python` | 26 файлов с исходниками и конфигурацией; телеметрия выключена | 3 сигнала: два использования MD5 и один `shell=True`. Совпадает по механизму с Bandit. |
| [Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks), встроенные правила | Файлы до 3 МБ, без вложенных архивов, в выводе редактируются секреты | 4 сигнала. Три уже отражены в отчёте; ключ из примера curl в документации совпадает с ключом API в исходнике. |
| [ModelScan 0.8.8](https://github.com/protectai/modelscan) с h5py 3.15.1 | Три распознанных легаси-артефакта | 9 сигналов: по четыре оператора в Pickle и Joblib, один слой Lambda в HDF5. Все уже покрывались. Второй поток Joblib отдельно доказан нашим правилом. |
| [pip-audit 2.10.1](https://github.com/pypa/pip-audit), PyPI | Четыре точных пина из `requirements.txt` и `docker-constraints.txt`, без установки и разрешения транзитивных зависимостей | 95 записей базы; после сведения CVE, GHSA и PYSEC остаётся 61 уникальный advisory на пару «пакет, версия». 13 связаны с нашим отчётом, 48 оставлены для дальнейшей проверки. |

Хеш фактически использованного набора `p/python`: `de5bc79d074c3b4146338a0bf95830406f169bd91ac590a2f1ef111f162e23f5`. Правила были скачаны до сканирования. База PyPI меняется, поэтому результат нового сетевого прогона может отличаться. `listed_fixes` в JSON перечисляет версии из базы; при расхождении проверяйте исходный advisory и нужную ветку.

## Что перенесено в основной профиль

- **Bandit B104:** открытый адрес по умолчанию в `src/api/config.py:4` доходит до HTTPServer. Compose публикует порт. Это риск конфигурации, доступность зависит от сети.
- **Bandit B108:** сигнал на строку с путём в `src/cache/store.py:7` связан с фактическим вызовом SQLite на строке 18. При запуске без монтирования Compose используется предсказуемое имя в общем `/tmp`. Строки в вспомогательной функции и в легаси-образце не посчитаны новыми проблемами SQLite.
- **Bandit B607:** `src/executor/runner.py:15` выбирает исполняемый файл через PATH. Для подмены нужен контроль пути поиска. B603 на той же строке общий и отдельно не считается. B404 отмечает импорт subprocess, который сам по себе уязвимости не доказывает.
- **Gitleaks:** подтверждено повторное раскрытие ключа в `docs/readme.md:32`. Это второе место раскрытия одного ключа, а не два разных ключа.
- **Ручная проверка HTTP:** `src/api/server.py:26` передаёт Content-Length напрямую в чтение тела; предел и таймаут не применяются. Добавлен детектор этой формы вызова.
- **Семь проверенных CVE:** три для [Requests](https://www.cve.org/CVERecord?id=CVE-2018-18074) ([.netrc](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7), [временный файл](https://github.com/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2)), [urllib3](https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4), Transformers ([MaskFormer](https://www.zerodayinitiative.com/advisories/ZDI-24-1514/), [Trax](https://www.zerodayinitiative.com/advisories/ZDI-24-1515/)) и [PyTorch](https://github.com/pytorch/pytorch/security/advisories/GHSA-63cw-57p8-fm3p). Подтверждено совпадение версии с диапазоном. Для эксплуатации нужны условия из комментариев триажа.

**Отсечённый шум.** Bandit B324 и Semgrep нашли MD5 и в генераторе, и в обёртке. Здесь он формирует ключ записи, а подлинность проверяет HMAC SHA-256. B311 указывает на случайный идентификатор ответа, не на секрет. B615 отмечает отсутствие закреплённой ревизии при `from_pretrained`, но штатный вызов читает локальный путь. B310 видит вызов `urlopen`; специальное правило объясняет, что его активирует вывод модели. Сам по себе B310 не доказывает SSRF. Некоторые записи PyPI требуют отдельной сверки диапазона или спорны: например, описание CVE-2025-55553 говорит о Torch 2.7.0, а база вернула сигнал и для 2.4.0. Из-за этого 61 совпадение нельзя прибавлять к числу находок стенда.

После сверки с внешними инструментами основной отчёт содержал 50 срабатываний. Последующий полный проход SafeTensors добавил 14 статистических сигналов эталонной модели. Актуальные решения по всем сигналам доступны в отчёте триажа.

## Повтор прогона

Запускать в окружении с установленными указанными версиями инструментов. Для Python-инструментов подходят `bandit==1.9.4`, `pip-audit==2.10.1`, `modelscan[h5py]==0.8.8` и `h5py==3.15.1`. Инструменты устанавливаются отдельно от проверяемого стенда. Сохраните набор Semgrep в локальный файл; для точного сравнения проверьте SHA-256 выше.

Из корня проекта:

```sh
export SFS_INPUT_DIR="/absolute/path/to/task_export"
export AUDIT_DIR="$(mktemp -d)"
export SEMGREP_RULES="/absolute/path/to/semgrep-python.yml"
python3 -m backend.sfs_oss --input "$SFS_INPUT_DIR" --print-pins > "$AUDIT_DIR/pins.txt"
# Выход 1 у Bandit, Gitleaks, ModelScan и pip-audit может означать находки. Проверяйте наличие JSON.
(
  cd "$SFS_INPUT_DIR" || exit 1
  bandit -r src model/_fixtures seed_cache.py --ignore-nosec -f json -q -o "$AUDIT_DIR/bandit.json"
  semgrep scan --metrics=off --disable-version-check --no-git-ignore --no-rewrite-rule-ids \
    --config "$SEMGREP_RULES" --json --output "$AUDIT_DIR/semgrep.json" \
    src model/_fixtures seed_cache.py Dockerfile docker-compose.yml
  gitleaks dir --redact=100 --max-target-megabytes 3 --report-format json --report-path "$AUDIT_DIR/gitleaks.json" .
  modelscan -p model -r json -o "$AUDIT_DIR/modelscan.json"
)
pip-audit -r "$AUDIT_DIR/pins.txt" --no-deps --disable-pip --vulnerability-service pypi \
  --format json --aliases on --output "$AUDIT_DIR/pip-audit.json"
python3 -m backend.sfs_oss --input "$SFS_INPUT_DIR" --report docs/sfs-report.json \
  --bandit "$AUDIT_DIR/bandit.json" --semgrep "$AUDIT_DIR/semgrep.json" \
  --gitleaks "$AUDIT_DIR/gitleaks.json" --modelscan "$AUDIT_DIR/modelscan.json" \
  --pip-audit "$AUDIT_DIR/pip-audit.json" > "$AUDIT_DIR/comparison.json"
```

Для других входов передайте их собственный отчёт триажа. Импорт сверяет пути и точные пины, связывает эквивалентные правила и оставляет необъяснённые записи для проверки. Сырые отчёты держите локально: там могут быть фрагменты кода. В обычном CI на Мос.Хабе новые встроенные правила работают офлайн; внешние инструменты и сетевые запросы не обязательны.
