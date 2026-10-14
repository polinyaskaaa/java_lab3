package ua.kpi.comsys.streams;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class SecurityLogAnalyzerTest {

    private final SecurityLogAnalyzer analyzer = new SecurityLogAnalyzer();
    private final LocalDateTime start = LocalDateTime.of(2025, 1, 1, 12, 0);

    private SecurityLog log(String ip, String level) {
        return new SecurityLog(ip, level, "test event", start);
    }

    // findFirstCriticalEvent

    @Test
    @DisplayName("findFirstCriticalEvent: null stream throws exception")
    void testFindCriticalNull() {
        Exception ex = assertThrows(IllegalArgumentException.class,
                () -> analyzer.findFirstCriticalEvent(null));
        assertEquals("stream cannot be null", ex.getMessage());
    }

    @Test
    @DisplayName("findFirstCriticalEvent: finds first critical in finite stream")
    void testFindCriticalFinite() {
        Stream<SecurityLog> stream = Stream.of(
                log("10.0.0.1", "INFO"),
                log("10.0.0.2", "CRITICAL"),
                log("10.0.0.3", "CRITICAL"));

        Optional<SecurityLog> res = analyzer.findFirstCriticalEvent(stream);

        assertTrue(res.isPresent());
        assertEquals("10.0.0.2", res.map(SecurityLog::ipAddress).orElse(""));
    }

    @Test
    @DisplayName("findFirstCriticalEvent: no critical events returns empty")
    void testFindCriticalNotFound() {
        Stream<SecurityLog> stream = Stream.of(log("10.0.0.1", "INFO"), log("10.0.0.2", "WARNING"));

        assertTrue(analyzer.findFirstCriticalEvent(stream).isEmpty());
    }

    @Test
    @DisplayName("findFirstCriticalEvent: lower case 'critical' does not count")
    void testFindCriticalCase() {
        Stream<SecurityLog> stream = Stream.of(log("10.0.0.1", "critical"));

        assertTrue(analyzer.findFirstCriticalEvent(stream).isEmpty());
    }

    @Test
    @Timeout(2)
    @DisplayName("findFirstCriticalEvent: works on infinite stream")
    void testFindCriticalInfinite() {
        Stream<SecurityLog> stream = Stream.iterate(1, i -> i + 1)
                .map(i -> log("10.0.0." + i, i == 50 ? "CRITICAL" : "INFO"));

        Optional<SecurityLog> res = analyzer.findFirstCriticalEvent(stream);

        assertEquals("10.0.0.50", res.map(SecurityLog::ipAddress).orElse("not found"));
    }

    // getLogsBeforeDeadline

    @Test
    @DisplayName("getLogsBeforeDeadline: null arguments throw exception")
    void testDeadlineNull() {
        assertThrows(IllegalArgumentException.class,
                () -> analyzer.getLogsBeforeDeadline(null, start));
        Exception ex = assertThrows(IllegalArgumentException.class,
                () -> analyzer.getLogsBeforeDeadline(Stream.empty(), null));
        assertEquals("deadline cannot be null", ex.getMessage());
    }

    @Test
    @Timeout(2)
    @DisplayName("getLogsBeforeDeadline: takes logs until deadline from infinite stream")
    void testDeadlineInfinite() {
        Stream<SecurityLog> stream = Stream.iterate(start, t -> t.plusMinutes(1))
                .map(t -> new SecurityLog("10.0.0.1", "INFO", "login", t));

        List<SecurityLog> res = analyzer.getLogsBeforeDeadline(stream, start.plusMinutes(5));

        assertEquals(5, res.size());
        assertEquals(start, res.get(0).timestamp());
        assertEquals(start.plusMinutes(4), res.get(4).timestamp());
    }

    @Test
    @Timeout(2)
    @DisplayName("getLogsBeforeDeadline: deadline before first log returns empty list")
    void testDeadlineBeforeFirst() {
        Stream<SecurityLog> stream = Stream.generate(() -> log("10.0.0.1", "INFO"));

        assertTrue(analyzer.getLogsBeforeDeadline(stream, start.minusHours(1)).isEmpty());
    }

    @Test
    @DisplayName("getLogsBeforeDeadline: log exactly at deadline is not included")
    void testDeadlineExact() {
        Stream<SecurityLog> stream = Stream.of(
                new SecurityLog("10.0.0.1", "INFO", "a", start),
                new SecurityLog("10.0.0.1", "INFO", "b", start.plusMinutes(1)),
                new SecurityLog("10.0.0.1", "INFO", "c", start.plusMinutes(2)));

        List<SecurityLog> res = analyzer.getLogsBeforeDeadline(stream, start.plusMinutes(1));

        assertEquals(1, res.size());
        assertEquals("a", res.get(0).eventDescription());
    }

    @Test
    @DisplayName("getLogsBeforeDeadline: finite stream that ends before deadline")
    void testDeadlineFiniteStream() {
        Stream<SecurityLog> stream = Stream.of(log("10.0.0.1", "INFO"), log("10.0.0.2", "INFO"));

        assertEquals(2, analyzer.getLogsBeforeDeadline(stream, start.plusDays(1)).size());
    }

    // detectIpBursts

    @Test
    @DisplayName("detectIpBursts: invalid arguments throw exception")
    void testBurstsInvalidArgs() {
        assertThrows(IllegalArgumentException.class,
                () -> analyzer.detectIpBursts(null, 3, 1));

        Exception ex1 = assertThrows(IllegalArgumentException.class,
                () -> analyzer.detectIpBursts(Stream.empty(), 0, 1));
        assertEquals("burstThreshold must be greater than 0", ex1.getMessage());

        Exception ex2 = assertThrows(IllegalArgumentException.class,
                () -> analyzer.detectIpBursts(Stream.empty(), 3, -1));
        assertEquals("maxIpsToReport must be greater than 0", ex2.getMessage());
    }

    @Test
    @DisplayName("detectIpBursts: finds burst in finite stream")
    void testBurstsFinite() {
        Stream<SecurityLog> stream = Stream.of(
                log("10.0.0.1", "INFO"),
                log("10.0.0.2", "INFO"),
                log("10.0.0.2", "INFO"),
                log("10.0.0.2", "INFO"),
                log("10.0.0.1", "INFO"));

        assertEquals(List.of("10.0.0.2"), analyzer.detectIpBursts(stream, 3, 5));
    }

    @Test
    @DisplayName("detectIpBursts: series broken by other ip is not a burst")
    void testBurstsBrokenSeries() {
        Stream<SecurityLog> stream = Stream.of(
                log("10.0.0.1", "INFO"),
                log("10.0.0.1", "INFO"),
                log("10.0.0.2", "INFO"),
                log("10.0.0.1", "INFO"),
                log("10.0.0.1", "INFO"));

        assertTrue(analyzer.detectIpBursts(stream, 3, 5).isEmpty());
    }

    @Test
    @DisplayName("detectIpBursts: same ip is reported only once")
    void testBurstsNoDuplicates() {
        Stream<SecurityLog> stream = Stream.of(
                log("10.0.0.1", "INFO"),
                log("10.0.0.1", "INFO"),
                log("10.0.0.2", "INFO"),
                log("10.0.0.1", "INFO"),
                log("10.0.0.1", "INFO"),
                log("10.0.0.1", "INFO"));

        assertEquals(List.of("10.0.0.1"), analyzer.detectIpBursts(stream, 2, 5));
    }

    @Test
    @Timeout(2)
    @DisplayName("detectIpBursts: stops on infinite stream after maxIpsToReport")
    void testBurstsInfinite() {
        // each ip sends 3 events in a row: 10.0.0.0 x3, 10.0.0.1 x3, ...
        Stream<SecurityLog> stream = Stream.iterate(0, i -> i + 1)
                .map(i -> log("10.0.0." + (i / 3), "WARNING"));

        List<String> res = analyzer.detectIpBursts(stream, 3, 2);

        assertEquals(List.of("10.0.0.0", "10.0.0.1"), res);
    }

    @Test
    @Timeout(2)
    @DisplayName("detectIpBursts: one ip spamming forever is reported once")
    void testBurstsInfiniteSameIp() {
        Stream<SecurityLog> stream = Stream.generate(() -> log("10.0.0.7", "WARNING"));

        assertEquals(List.of("10.0.0.7"), analyzer.detectIpBursts(stream, 10, 1));
    }

    @Test
    @Timeout(2)
    @DisplayName("detectIpBursts: series shorter than threshold is not a burst")
    void testBurstsShortSeries() {
        Stream<SecurityLog> stream = Stream.generate(() -> log("10.0.0.7", "WARNING")).limit(4);

        assertTrue(analyzer.detectIpBursts(stream, 5, 1).isEmpty());
    }
}
