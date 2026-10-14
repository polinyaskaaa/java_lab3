# Лабораторна робота №3 — Stream API, Optional та Stream Gatherers

**Дисципліна:** Технології розробки на платформі Java
**Тема:** Опрацювання нескінченних послідовностей даних за допомогою ледачих операцій Java Stream API, Optional та Stream Gatherers
**Виконала:** Студентка групи ІС-41 Малик Поліна

## Розрахунок варіанта

Для обчислення варіанту було використано порядковий номер у списку групи: **N = 11**.

```
V = N mod 3 = 11 mod 3 = 2
```

Таким чином отримали **Варіант V = 2** — обробка безпекових подій (`SecurityLogAnalyzer`).

## Опис проєкту

Усі класи знаходяться в пакеті `ua.kpi.comsys.streams`.

Модель даних — запис `SecurityLog(String ipAddress, String severityLevel, String eventDescription, LocalDateTime timestamp)`.

Клас `SecurityLogAnalyzer` працює як зі скінченними, так і з нескінченними стрімами:

| Метод | Що робить | Як |
|-------|-----------|-----|
| `Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream)` | перша подія з рівнем `"CRITICAL"` | `filter` + `findFirst` (коротке замикання) |
| `List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream, LocalDateTime deadline)` | події, доки не настане дедлайн (подія рівно в момент дедлайну не входить) | `takeWhile` |
| `List<String> detectIpBursts(Stream<SecurityLog> stream, int burstThreshold, int maxIpsToReport)` | IP-адреси, від яких надійшло `>= burstThreshold` подій поспіль | власний `Gatherer` |

### Gatherer для детекції Burst-атак

Створюється через `Gatherer.ofSequential` і зберігає стан:

- поточну IP-адресу та довжину її неперервної серії;
- множину вже знайдених IP.

Коли серія однієї IP досягає `burstThreshold`, ця IP передається далі (кожна IP — лише один раз). Щойно знайдено `maxIpsToReport` адрес, Gatherer повертає `false` і обробка нескінченного стріму зупиняється.

### Валідація

- `stream == null` → `IllegalArgumentException("stream cannot be null")`;
- `deadline == null` → `IllegalArgumentException("deadline cannot be null")`;
- `burstThreshold <= 0` → `IllegalArgumentException("burstThreshold must be greater than 0")`;
- `maxIpsToReport <= 0` → `IllegalArgumentException("maxIpsToReport must be greater than 0")`.

### Структура

```
gradle/libs.versions.toml      Version Catalog (JUnit 5)
build.gradle.kts               конфігурація збірки (Java 25)
settings.gradle.kts
gradlew, gradlew.bat, gradle/wrapper/   Gradle Wrapper 9.8.1
src/main/java/ua/kpi/comsys/streams/SecurityLog.java
src/main/java/ua/kpi/comsys/streams/SecurityLogAnalyzer.java
src/test/java/ua/kpi/comsys/streams/SecurityLogAnalyzerTest.java
```

## Тести

Тести перевіряють звичайні сценарії, невірні аргументи та роботу з нескінченними стрімами
(`Stream.iterate`, `Stream.generate`). Тести з нескінченними стрімами позначені `@Timeout(2)`,
щоб підтвердити, що обробка не зависає.

## Запуск тестів

Потрібен JDK 17+ для запуску Gradle. Код компілюється під Java 25: якщо JDK 25 не встановлений,
Gradle завантажить його автоматично. Gradle встановлювати не треба — використовується wrapper.

```bash
./gradlew build     # збірка + тести
./gradlew test      # лише тести
```

У Windows: `gradlew.bat test`. HTML-звіт тестів: `build/reports/tests/test/index.html`.
