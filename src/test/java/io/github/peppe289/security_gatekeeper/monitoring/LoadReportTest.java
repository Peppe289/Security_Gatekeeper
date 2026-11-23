package io.github.peppe289.security_gatekeeper.monitoring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.monitoring.LoadReport.Level;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/**
 * Levels and verdict of the load report. The thresholds (50%, 70%, 90%) are tested with
 * boundary values: exactly on each threshold and just below it.
 */
class LoadReportTest {

    private static final Duration INTERVAL = Duration.ofSeconds(5);
    private static final Duration WINDOW = Duration.ofMinutes(15);
    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");
    private static final int WORKERS = 200;
    private static final int AUDIT_CAPACITY = 1000;

    /** A sample where only the CPU is loaded; every other resource is idle. */
    private static LoadMonitor.Sample cpuSample(Instant at, double cpu) {
        SystemProbe.Reading reading = new SystemProbe.Reading(cpu, 2, 0, 100, 0, 100, 0, 0);
        return new LoadMonitor.Sample(at, reading, 0, 0, 0, 0, 0);
    }

    private static LoadReport report(double... cpu) {
        List<LoadMonitor.Sample> samples = new java.util.ArrayList<>();
        for (int i = 0; i < cpu.length; i++) {
            samples.add(cpuSample(T0.plus(INTERVAL.multipliedBy(i)), cpu[i]));
        }
        return LoadReport.from(samples, WORKERS, AUDIT_CAPACITY, INTERVAL, WINDOW);
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
            "0.0,    OK",
            "0.6999, OK",
            "0.70,   HIGH",
            "0.8999, HIGH",
            "0.90,   CRITICAL",
            "1.0,    CRITICAL",
            "NaN,    UNKNOWN"})
    void levelBoundaries(double fraction, Level expected) {
        assertEquals(expected, Level.of(fraction));
    }

    @ParameterizedTest(name = "peak {0} -> {1}: {2}")
    @CsvSource({
            "0.4999, OK,       Plenty of headroom",
            "0.50,   OK,       Moderate load",
            "0.6999, OK,       Moderate load",
            "0.70,   HIGH,     Approaching the limit",
            "0.8999, HIGH,     Approaching the limit",
            "0.90,   CRITICAL, Saturated"})
    void verdictBoundaries(double peak, Level level, String message) {
        LoadReport.Verdict verdict = report(peak).verdict();

        assertEquals(level, verdict.level());
        assertTrue(verdict.message().startsWith(message), verdict.message());
        assertTrue(verdict.message().contains("CPU"), "names the most loaded resource");
    }

    @Test
    void verdictUsesThePeakOfTheWindowNotTheCurrentValue() {
        LoadReport report = report(0.95, 0.10);

        assertEquals(Level.CRITICAL, report.verdict().level());
        LoadReport.Meter cpu = report.meters().get(0);
        assertEquals(0.10, cpu.current(), 1e-9);
        assertEquals(0.95, cpu.peak(), 1e-9);
    }

    @Test
    void noSamplesMeansStillCollecting() {
        LoadReport report = LoadReport.from(List.of(), WORKERS, AUDIT_CAPACITY, INTERVAL, WINDOW);

        assertEquals(Level.UNKNOWN, report.verdict().level());
        assertTrue(report.meters().isEmpty());
        assertEquals(0, report.samples());
    }

    @Test
    void nothingMeasurableMeansUnknown() {
        SystemProbe.Reading unknown = new SystemProbe.Reading(Double.NaN, 1, -1, -1, -1, -1, -1, -1);
        LoadMonitor.Sample sample = new LoadMonitor.Sample(T0, unknown, 0, 0, Double.NaN, Double.NaN, Double.NaN);
        // Workers and audit queue are always measurable: give them no capacity to hide them too.
        LoadReport report = LoadReport.from(List.of(sample), 0, 0, INTERVAL, WINDOW);

        assertEquals(Level.UNKNOWN, report.verdict().level());
        assertFalse(report.meters().get(0).measured());
    }

    @Test
    void coveredTimeIsCappedAtTheWindow() {
        double[] many = new double[400]; // 400 samples x 5 s = more than 15 min
        assertEquals(WINDOW, report(many).covered());
        assertEquals(Duration.ofSeconds(10), report(0, 0).covered());
    }

    @ParameterizedTest(name = "{0} B -> {1}")
    @CsvSource({"-1, n/a", "0, 0 B", "1023, 1023 B", "1024, 1.0 KiB", "1572864, 1.5 MiB"})
    void bytesFormatting(long bytes, String expected) {
        assertEquals(expected, LoadReport.bytes(bytes));
    }

    @ParameterizedTest(name = "{0} s -> {1}")
    @CsvSource({"0, 1 s", "119, 119 s", "120, 2 min", "900, 15 min"})
    void durationFormatting(long seconds, String expected) {
        assertEquals(expected, LoadReport.duration(Duration.ofSeconds(seconds)));
    }
}
