package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Gatherer;
import java.util.stream.Stream;

public class SecurityLogAnalyzer {

    private static final String CRITICAL = "CRITICAL";

    public Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream) {
        checkNull(stream, "stream");
        return stream
                .filter(Objects::nonNull)
                .filter(log -> CRITICAL.equals(log.severityLevel()))
                .findFirst();
    }

    public List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream, LocalDateTime deadline) {
        checkNull(stream, "stream");
        checkNull(deadline, "deadline");
        return stream
                .filter(Objects::nonNull)
                .takeWhile(log -> Optional.ofNullable(log.timestamp())
                        .map(time -> time.isBefore(deadline))
                        .orElse(false))
                .toList();
    }

    public List<String> detectIpBursts(Stream<SecurityLog> stream, int burstThreshold, int maxIpsToReport) {
        checkNull(stream, "stream");
        if (burstThreshold <= 0) {
            throw new IllegalArgumentException("burstThreshold must be greater than 0");
        }
        if (maxIpsToReport <= 0) {
            throw new IllegalArgumentException("maxIpsToReport must be greater than 0");
        }
        return stream
                .filter(Objects::nonNull)
                .gather(burstDetector(burstThreshold, maxIpsToReport))
                .toList();
    }

    private static Gatherer<SecurityLog, ?, String> burstDetector(int threshold, int maxIps) {
        class State {
            String ip;
            int count;
            final Set<String> reported = new HashSet<>();
        }

        return Gatherer.ofSequential(
                State::new,
                (state, log, downstream) -> {
                    String ip = log.ipAddress();
                    if (ip != null && ip.equals(state.ip)) {
                        state.count++;
                    } else {
                        state.ip = ip;
                        state.count = ip == null ? 0 : 1;
                    }

                    if (state.count == threshold && state.reported.add(ip)) {
                        downstream.push(ip);
                    }
                    return state.reported.size() < maxIps && !downstream.isRejecting();
                });
    }

    private static void checkNull(Object value, String name) {
        Optional.ofNullable(value)
                .orElseThrow(() -> new IllegalArgumentException(name + " cannot be null"));
    }
}
