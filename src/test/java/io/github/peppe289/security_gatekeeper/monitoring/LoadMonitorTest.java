package io.github.peppe289.security_gatekeeper.monitoring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LoadMonitorTest {

    private static final long GIB = 1L << 30;

    private final MutableClock clock = new MutableClock();
    private final InFlightRequests inFlight = new InFlightRequests();
    private final AtomicLong requests = new AtomicLong();
    private final AtomicInteger queued = new AtomicInteger();
    private SystemProbe.Reading reading;
    private LoadMonitor monitor;

    @BeforeEach
    void setUp() {
        reading = reading(0.10, 0, 0);
        monitor = new LoadMonitor(() -> reading, inFlight, requests::get, queued::get, 1000, 200, clock,
                Duration.ofSeconds(5), Duration.ofSeconds(20));
    }

    private static SystemProbe.Reading reading(double cpu, long rx, long tx) {
        return new SystemProbe.Reading(cpu, 2, GIB / 4, GIB, 100L << 20, 400L << 20, rx, tx);
    }

    private void tick() {
        clock.advance(Duration.ofSeconds(5));
        monitor.sample();
    }

    private LoadReport.Meter meter(LoadReport report, String name) {
        return report.meters().stream().filter(m -> m.name().equals(name)).findFirst().orElseThrow();
    }

    private LoadReport.Trend trend(LoadReport report, String name) {
        return report.trends().stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
    }

    @Test
    void noSampleYet() {
        LoadReport report = monitor.report();
        assertNull(report.sampledAt());
        assertEquals(LoadReport.Level.UNKNOWN, report.verdict().level());
        assertTrue(report.meters().isEmpty());
    }

    @Test
    void ratesComeFromCounterDeltas() {
        reading = reading(0.10, 1_000, 0);
        requests.set(100);
        tick();
        reading = reading(0.10, 6_000, 1_250);
        requests.set(150);
        tick();

        LoadReport report = monitor.report();
        assertEquals("8.0 kbit/s", trend(report, "Network in").current(), "5000 B in 5 s");
        assertEquals("2.0 kbit/s", trend(report, "Network out").current());
        assertEquals("10.0 req/s", trend(report, "Requests").current());
    }

    @Test
    void unavailableNetworkIsReportedAsSuch() {
        reading = reading(0.10, -1, -1);
        tick();
        tick();
        LoadReport.Trend in = trend(monitor.report(), "Network in");
        assertFalse(in.measured());
        assertEquals("n/a", in.current());
    }

    @Test
    void levelsFollowThePeakNotTheCurrentValue() {
        reading = reading(0.95, 0, 0);
        tick();
        reading = reading(0.20, 0, 0);
        tick();

        LoadReport report = monitor.report();
        LoadReport.Meter cpu = meter(report, "CPU");
        assertEquals("20%", cpu.currentText());
        assertEquals("95%", cpu.peakText());
        assertEquals(LoadReport.Level.CRITICAL, cpu.level());
        assertEquals(LoadReport.Level.CRITICAL, report.verdict().level());
        assertTrue(report.verdict().message().startsWith("Saturated: CPU peaked at 95%"), report.verdict().message());
    }

    @Test
    void peaksLeaveTheWindow() {
        reading = reading(0.95, 0, 0);
        tick();
        reading = reading(0.20, 0, 0);
        for (int i = 0; i < 4; i++) {
            tick(); // window of 20 s at 5 s: 4 samples are kept
        }
        LoadReport report = monitor.report();
        assertEquals(4, report.samples());
        assertEquals("20%", meter(report, "CPU").peakText());
        assertEquals(LoadReport.Level.OK, report.verdict().level());
        assertTrue(report.verdict().message().startsWith("Plenty of headroom"), report.verdict().message());
    }

    @Test
    void workerPeakBetweenSamplesIsNotMissed() {
        for (int i = 0; i < 160; i++) {
            inFlight.enter();
        }
        for (int i = 0; i < 160; i++) {
            inFlight.exit();
        }
        tick();
        LoadReport.Meter workers = meter(monitor.report(), "Worker threads");
        assertEquals("80%", workers.currentText(), "160 of 200, although none is busy at sampling time");
        assertEquals(LoadReport.Level.HIGH, workers.level());

        tick();
        assertEquals("0%", meter(monitor.report(), "Worker threads").currentText());
    }

    @Test
    void auditQueueAndMemoryAreRatiosOfTheirLimits() {
        queued.set(950);
        tick();
        LoadReport report = monitor.report();
        assertEquals("95%", meter(report, "Audit queue").currentText());
        assertEquals("25%", meter(report, "Memory").currentText());
        assertEquals("25%", meter(report, "JVM heap").currentText());
        assertEquals("Audit queue", report.verdict().message().split(" peaked")[0].replace("Saturated: ", ""));
    }

    @Test
    void sparklineStaysInsideItsBox() {
        reading = reading(0.0, 0, 0);
        tick();
        reading = reading(1.0, 0, 0);
        tick();
        LoadReport.Trend cpu = trend(monitor.report(), "CPU");
        assertEquals("0.0,51.0 240.0,5.0", cpu.points());
        assertEquals(240.0, cpu.lastX());
        assertEquals(5.0, cpu.lastY());
    }

    @Test
    void formatting() {
        assertEquals("512 B", LoadReport.bytes(512));
        assertEquals("1.5 GiB", LoadReport.bytes(3 * GIB / 2));
        assertEquals("950 bit/s", LoadReport.bits(950));
        assertEquals("1.2 Gbit/s", LoadReport.bits(1.2e9));
        assertEquals("45 s", LoadReport.duration(Duration.ofSeconds(45)));
        assertEquals("15 min", LoadReport.duration(Duration.ofMinutes(15)));
    }

    private static final class MutableClock extends Clock {

        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
