package io.github.peppe289.security_gatekeeper.audit;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Where {@link AuditAnchor}s are kept, outside the database.
 *
 * <p>Every anchor is written to the log (so a log shipper can keep a copy) and,
 * if {@code gateway.audit.anchor-dir} is set, appended to
 * {@code <anchor-dir>/<nodeId>.anchors}. Only the directory can be read back
 * for automatic verification; to check every node's chain from any node, the
 * directory must be shared (e.g. a common volume).
 */
@Component
public class AuditAnchorStore {

    private static final Logger log = LoggerFactory.getLogger(AuditAnchorStore.class);
    private static final String EXTENSION = ".anchors";

    private final Path dir;

    @Autowired
    public AuditAnchorStore(GatewayProperties properties) {
        this(properties.audit().anchorDir() == null ? null : Path.of(properties.audit().anchorDir()));
    }

    AuditAnchorStore(Path dir) {
        this.dir = dir;
    }

    /** @return {@code true} if anchors are written to a directory that verification can read */
    public boolean isPersistent() {
        return dir != null;
    }

    /** Creates the anchor directory if needed. */
    void init() throws IOException {
        if (dir != null) {
            Files.createDirectories(dir);
        }
    }

    /** Records {@code anchor} in the log and, if configured, durably in the anchor directory. */
    void append(AuditAnchor anchor) throws IOException {
        log.info("Audit anchor: node={} sequence={} hash={} timestamp={} key={} mac={}", anchor.nodeId(),
                anchor.sequence(), anchor.hash(), anchor.timestampMillis(), anchor.keyId(), anchor.mac());
        if (dir != null) {
            Files.writeString(file(anchor.nodeId()), anchor.toLine() + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND,
                    StandardOpenOption.SYNC);
        }
    }

    /**
     * Reads every anchor in the directory, grouped by node and in file order.
     *
     * @return an empty map if no directory is configured
     * @throws IOException if the directory is missing or a file cannot be read or parsed
     */
    Map<String, List<AuditAnchor>> loadAll() throws IOException {
        if (dir == null) {
            return Map.of();
        }
        if (!Files.isDirectory(dir)) {
            throw new NoSuchFileException(dir.toString(), null, "anchor directory is missing");
        }
        Map<String, List<AuditAnchor>> byNode = new TreeMap<>();
        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, "*" + EXTENSION)) {
            for (Path f : files) {
                String fileName = f.getFileName().toString();
                String node = fileName.substring(0, fileName.length() - EXTENSION.length());
                byNode.put(node, read(f, node));
            }
        }
        return byNode;
    }

    private static List<AuditAnchor> read(Path f, String node) throws IOException {
        List<AuditAnchor> anchors = new ArrayList<>();
        List<String> lines = Files.readAllLines(f, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).isBlank()) {
                continue;
            }
            AuditAnchor a;
            try {
                a = AuditAnchor.parse(lines.get(i));
            } catch (IllegalArgumentException e) {
                throw new IOException("malformed anchor at " + f.getFileName() + ":" + (i + 1), e);
            }
            if (!a.nodeId().equals(node)) {
                throw new IOException("anchor of node '" + a.nodeId() + "' in " + f.getFileName() + ":" + (i + 1));
            }
            anchors.add(a);
        }
        return anchors;
    }

    private Path file(String nodeId) {
        return dir.resolve(nodeId + EXTENSION);
    }
}
