# BPMN benchmark

Локальная проверка результатов генерации BPMN: XML/XSD, обязательные требования, сценарии с токенами и смысловые вердикты Codex.

В репозитории три **синтетических мока**: согласование доступа, цикл доработки документа и параллельные проверки заказа. Они проверяют работу оценщика; для измерения качества сервиса нужно загрузить реальный бенчмарк.

## Быстрый старт

Нужны Python 3.10+ и xmllint. Python-зависимости устанавливать не требуется.

~~~sh
git clone https://github.com/Winkey86/bpmn-benchmark.git
cd bpmn-benchmark
python3 -m unittest discover -s tests -v
python3 tools/benchmark.py run --demo --out runs/try-001
~~~

До смысловой оценки итог демо — REVIEW, код завершения 2. Это ожидаемый результат.

## Проверка сервиса

Готовые ответы сервиса: по одному файлу CASE_ID.bpmn на кейс в каталоге outputs.

~~~sh
python3 tools/benchmark.py run --candidates outputs --out runs/service-001
~~~

Для генерации внутри прогона:

~~~sh
python3 tools/benchmark.py run --generator "python3 /path/to/service_adapter.py" --out runs/service-002
~~~

Адаптер читает JSON с case_id и prompt из stdin и возвращает BPMN XML в stdout. Ошибки и пропуски учитываются как FAIL.

После заполнения вердиктов Codex:

~~~sh
python3 tools/benchmark.py finalize runs/service-001
~~~

Полный порядок оценки, формат вердиктов и подключение реального набора: [инструкция для Codex](CODEX_BENCHMARK.md).

## Состав

| Файл | Назначение |
|---|---|
| [tools/benchmark.py](tools/benchmark.py) | Прогонщик, сценарии, итоговый отчёт |
| [tools/audit.py](tools/audit.py) | XML/XSD и ограниченные структурные проверки |
| [benchmark/mock/manifest.json](benchmark/mock/manifest.json) | Три моковых кейса с промптами, XML и проверками |
| [tests/test_benchmark.py](tests/test_benchmark.py) | Регрессионные тесты, включая намеренные ошибки |
| [CODEX_BENCHMARK.md](CODEX_BENCHMARK.md) | Инструкция для агента и формат реального бенчмарка |

Снимки входов, хеши, задания судье и отчёты JSON/Markdown сохраняются в отдельную папку запуска. Повторное использование существующей папки запрещено. PASS требует прохождения всех обязательных проверок.

## Границы

Сценарии поддерживают один плоский процесс, обычные задачи, пустые start/end, XOR и AND. Проверяются заданные ветви и порядки срабатывания; выражения условий и интеграции не исполняются. Неподдержанная семантика получает REVIEW, геометрия не оценивается.

XSD BPMN 2.0.2 в tools/vendor/bpmn-2.0.2 — из [спецификации OMG](https://www.omg.org/spec/BPMN/2.0.2/About-BPMN).
