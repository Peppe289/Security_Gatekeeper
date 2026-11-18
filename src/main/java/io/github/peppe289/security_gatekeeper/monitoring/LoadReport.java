package io.github.peppe289.security_gatekeeper.monitoring;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.DoubleFunction;
import java.util.function.ToDoubleFunction;

/**
 * What the dashboard shows about the load of this instance: one meter per
 * limited resource (current value and peak over the window), one trend per
 * rate, and a verdict naming the most loaded resource.
 *
 * <p>Levels are decided on the <em>peak</em> of the window, not on the current
 * value: the question is how much more traffic the instance can take, and
 * a resource that touched its limit a minute ago has no real headroom.
 *
 * @param sampledAt time of the latest sample, or {@code null} if none yet
 * @param covered   time span covered by the samples (at most the configured window)
 */
public record LoadReport(Instant sampledAt, Duration interval, Duration covered, int samples, Verdict verdict,
                         List<Meter> meters, List<Trend> trends) {

    static final double COMFORTABLE = 0.50;
    static final double HIGH = 0.70;
    static final double CRITICAL = 0.90;
    private static final double SPARK_PADDING = 5;

    /** Severity of a resource, with the CSS modifier and the text shown next to the color. */
    public enum Level {
        OK("ok", "OK"),
        HIGH("warn", "High"),
        CRITICAL("bad", "Critical"),
        UNKNOWN("none", "n/a");

        private final String css;
        private final String label;

        Level(String css, String label) {
            this.css = css;
            this.label = label;
        }

        public String css() {
            return css;
        }

        public String label() {
            return label;
        }

        static Level of(double fraction) {
            if (Double.isNaN(fraction)) {
                return UNKNOWN;
            }
            return fraction >= LoadReport.CRITICAL ? CRITICAL : fraction >= LoadReport.HIGH ? HIGH : OK;
        }
    }

    public record Verdict(Level level, String message) {
    }

    /**
     * A resource with a limit.
     *
     * @param current fraction of the limit in use at the latest sample, {@code NaN} if not measurable
     * @param peak    highest fraction over the window
     */
    public record Meter(String name, String detail, double current, double peak, Level level) {

        public boolean measured() {
            return !Double.isNaN(current);
        }

        public String currentText() {
            return percent(current);
        }

        public String peakText() {
            return percent(peak);
        }

        /** Bar length in the {@code 0..100} SVG coordinate space. */
        public double currentWidth() {
            return clampPercent(current);
        }

        /** Position of the peak tick in the {@code 0..100} SVG coordinate space. */
        public double peakX() {
            return clampPercent(peak);
        }
    }

    /**
     * A rate over time, drawn as a sparkline in a {@value #SPARK_WIDTH}×{@value #SPARK_HEIGHT}
     * SVG coordinate space with the baseline at zero.
     */
    public record Trend(String name, String current, String average, String peak, String points, double lastX,
                        double lastY, boolean measured, String description) {

        public static final int SPARK_WIDTH = 240;
        public static final int SPARK_HEIGHT = 56;
    }

    /** Time span covered by the samples, for display (e.g. {@code 15 min}). */
    public String coveredText() {
        return duration(covered);
    }

    /** Sampling interval, for display (e.g. {@code 5 s}). */
    public String intervalText() {
        return seconds(interval);
    }

    static LoadReport from(List<LoadMonitor.Sample> samples, int maxWorkers, int auditCapacity, Duration interval,
                           Duration window) {
        if (samples.isEmpty()) {
            Verdict verdict = new Verdict(Level.UNKNOWN, "Collecting data: the first sample is taken within "
                    + seconds(interval) + ".");
            return new LoadReport(null, interval, Duration.ZERO, 0, verdict, List.of(), List.of());
        }
        LoadMonitor.Sample last = samples.get(samples.size() - 1);
        Duration covered = Duration.between(samples.get(0).at(), last.at()).plus(interval);
        if (covered.compareTo(window) > 0) {
            covered = window;
        }
        SystemProbe.Reading r = last.reading();

        List<Meter> meters = List.of(
                meter("CPU", r.processors() + (r.processors() == 1 ? " CPU" : " CPUs") + " available to the container",
                        samples, s -> s.reading().cpuLoad()),
                meter("Memory", bytes(r.memoryUsed()) + " of " + bytes(r.memoryTotal()) + ", page cache included",
                        samples, s -> ratio(s.reading().memoryUsed(), s.reading().memoryTotal())),
                meter("JVM heap", bytes(r.heapUsed()) + " of " + bytes(r.heapMax()),
                        samples, s -> ratio(s.reading().heapUsed(), s.reading().heapMax())),
                meter("Worker threads", last.inFlightPeak() + " of " + maxWorkers
                                + " busy serving proxied requests (peak per sample)",
                        samples, s -> ratio(s.inFlightPeak(), maxWorkers)),
                meter("Audit queue", last.auditQueued() + " of " + auditCapacity + " events waiting to be written",
                        samples, s -> ratio(s.auditQueued(), auditCapacity)));

        String period = duration(covered);
        List<Trend> trends = List.of(
                trend("CPU", samples, s -> s.reading().cpuLoad() * 100, 100, v -> percent(v / 100), period),
                trend("Network in", samples, LoadMonitor.Sample::rxBitsPerSecond, 0, LoadReport::bits, period),
                trend("Network out", samples, LoadMonitor.Sample::txBitsPerSecond, 0, LoadReport::bits, period),
                trend("Requests", samples, LoadMonitor.Sample::requestsPerSecond, 0,
                        v -> String.format(Locale.ROOT, "%.1f req/s", v), period));

        return new LoadReport(last.at(), interval, covered, samples.size(), verdict(meters, period), meters, trends);
    }

    private static Verdict verdict(List<Meter> meters, String period) {
        Meter worst = null;
        for (Meter m : meters) {
            if (!Double.isNaN(m.peak()) && (worst == null || m.peak() > worst.peak())) {
                worst = m;
            }
        }
        if (worst == null) {
            return new Verdict(Level.UNKNOWN, "No resource could be measured on this platform.");
        }
        String what = worst.name() + " peaked at " + percent(worst.peak()) + " in the last " + period;
        if (worst.peak() < COMFORTABLE) {
            return new Verdict(Level.OK, "Plenty of headroom: the most loaded resource, " + what + ".");
        }
        if (worst.peak() < HIGH) {
            return new Verdict(Level.OK, "Moderate load: " + what
                    + ". There is room to grow; keep an eye on it as traffic increases.");
        }
        if (worst.peak() < CRITICAL) {
            return new Verdict(Level.HIGH, "Approaching the limit: " + what
                    + ". Add capacity before pushing more traffic.");
        }
        return new Verdict(Level.CRITICAL, "Saturated: " + what + ". This instance cannot take more traffic.");
    }

    private static Meter meter(String name, String detail, List<LoadMonitor.Sample> samples,
                               ToDoubleFunction<LoadMonitor.Sample> value) {
        double current = value.applyAsDouble(samples.get(samples.size() - 1));
        double peak = max(samples, value);
        return new Meter(name, detail, current, peak, Level.of(peak));
    }

    /**
     * @param scaleMax top of the vertical scale; {@code 0} to scale on the peak of the series
     */
    private static Trend trend(String name, List<LoadMonitor.Sample> samples, ToDoubleFunction<LoadMonitor.Sample> value,
                               double scaleMax, DoubleFunction<String> format, String period) {
        double peak = max(samples, value);
        if (Double.isNaN(peak)) {
            return new Trend(name, "n/a", "n/a", "n/a", "", 0, 0, false,
                    name + ": not measurable on this platform.");
        }
        double top = scaleMax > 0 ? scaleMax : Math.max(peak, 1e-9);
        double sum = 0;
        int count = 0;
        double current = Double.NaN;
        double lastX = 0;
        double lastY = 0;
        List<String> points = new ArrayList<>();
        int n = samples.size();
        double usable = Trend.SPARK_HEIGHT - 2.0 * SPARK_PADDING;
        for (int i = 0; i < n; i++) {
            double v = value.applyAsDouble(samples.get(i));
            if (i == n - 1) {
                current = v;
            }
            if (Double.isNaN(v)) {
                continue;
            }
            sum += v;
            count++;
            double x = n == 1 ? Trend.SPARK_WIDTH : (double) i * Trend.SPARK_WIDTH / (n - 1);
            double y = Trend.SPARK_HEIGHT - SPARK_PADDING - Math.min(1, Math.max(0, v / top)) * usable;
            points.add(String.format(Locale.ROOT, "%.1f,%.1f", x, y));
            lastX = x;
            lastY = y;
        }
        String currentText = Double.isNaN(current) ? "n/a" : format.apply(current);
        String averageText = format.apply(sum / count);
        String peakText = format.apply(peak);
        String description = name + ": now " + currentText + ", average " + averageText + ", peak " + peakText
                + " over the last " + period + ".";
        return new Trend(name, currentText, averageText, peakText, String.join(" ", points), lastX, lastY, true,
                description);
    }

    private static double max(List<LoadMonitor.Sample> samples, ToDoubleFunction<LoadMonitor.Sample> value) {
        double max = Double.NaN;
        for (LoadMonitor.Sample s : samples) {
            double v = value.applyAsDouble(s);
            if (!Double.isNaN(v) && (Double.isNaN(max) || v > max)) {
                max = v;
            }
        }
        return max;
    }

    private static double ratio(long used, long total) {
        return used < 0 || total <= 0 ? Double.NaN : (double) used / total;
    }

    private static double clampPercent(double fraction) {
        return Double.isNaN(fraction) ? 0 : Math.min(100, Math.max(0, fraction * 100));
    }

    static String percent(double fraction) {
        return Double.isNaN(fraction) ? "n/a" : Math.round(fraction * 100) + "%";
    }

    static String bytes(long bytes) {
        if (bytes < 0) {
            return "n/a";
        }
        String[] units = {"B", "KiB", "MiB", "GiB", "TiB"};
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < units.length - 1) {
            v /= 1024;
            u++;
        }
        return u == 0 ? bytes + " B" : String.format(Locale.ROOT, "%.1f %s", v, units[u]);
    }

    static String bits(double bitsPerSecond) {
        String[] units = {"bit/s", "kbit/s", "Mbit/s", "Gbit/s"};
        double v = bitsPerSecond;
        int u = 0;
        while (v >= 1000 && u < units.length - 1) {
            v /= 1000;
            u++;
        }
        return String.format(Locale.ROOT, u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
    }

    static String duration(Duration d) {
        long s = Math.max(1, d.toSeconds());
        if (s < 120) {
            return s + " s";
        }
        return Math.round(s / 60.0) + " min";
    }

    private static String seconds(Duration d) {
        return Math.max(1, d.toSeconds()) + " s";
    }
}
