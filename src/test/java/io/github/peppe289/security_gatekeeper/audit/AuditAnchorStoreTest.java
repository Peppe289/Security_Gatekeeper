package io.github.peppe289.security_gatekeeper.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuditAnchorStoreTest {

    private static final String HASH = "a".repeat(64);

    private final AuditKeys keys = new AuditKeys(AuditKeysTest.KEY, List.of());

    @TempDir
    Path dir;

    private AuditAnchor anchor(String node, long sequence) {
        return AuditAnchor.create(node, sequence, HASH, 1_700_000_000_000L + sequence, keys);
    }

    @Test
    void anchorsRoundTripPerNode() throws IOException {
        AuditAnchorStore store = new AuditAnchorStore(dir);
        store.append(anchor("node-a", 3));
        store.append(anchor("node-a", 9));
        store.append(anchor("node-b", 1));

        Map<String, List<AuditAnchor>> all = store.loadAll();
        assertEquals(List.of(anchor("node-a", 3), anchor("node-a", 9)), all.get("node-a"));
        assertEquals(List.of(anchor("node-b", 1)), all.get("node-b"));
        assertTrue(all.get("node-a").get(0).isAuthentic(keys));
    }

    @Test
    void alteredAnchorIsNotAuthentic() {
        AuditAnchor a = anchor("node-a", 3);
        AuditAnchor moved = new AuditAnchor(a.nodeId(), 2, a.hash(), a.timestampMillis(), a.keyId(), a.mac());
        assertFalse(moved.isAuthentic(keys));
    }

    @Test
    void lineFormatRoundTrips() {
        AuditAnchor a = anchor("node-a", 7);
        assertEquals(a, AuditAnchor.parse(a.toLine()));
        assertThrows(IllegalArgumentException.class, () -> AuditAnchor.parse("v1\tnode-a\t7"));
        assertThrows(IllegalArgumentException.class, () -> AuditAnchor.parse(a.toLine().replace("\t7\t", "\tx\t")));
        assertThrows(IllegalArgumentException.class, () -> AuditAnchor.parse(a.toLine().replaceFirst("v1", "v9")));
    }

    @Test
    void malformedOrMisplacedLinesFailLoading() throws IOException {
        AuditAnchorStore store = new AuditAnchorStore(dir);
        Files.writeString(dir.resolve("node-a.anchors"), "garbage\n", StandardCharsets.UTF_8);
        assertThrows(IOException.class, store::loadAll);

        Files.writeString(dir.resolve("node-a.anchors"), anchor("node-b", 1).toLine() + "\n", StandardCharsets.UTF_8,
                StandardOpenOption.TRUNCATE_EXISTING);
        assertThrows(IOException.class, store::loadAll, "anchor of another node");
    }

    @Test
    void missingDirectoryFailsLoading() throws IOException {
        AuditAnchorStore store = new AuditAnchorStore(dir.resolve("deleted"));
        assertThrows(IOException.class, store::loadAll);
        store.init();
        assertTrue(store.loadAll().isEmpty());
    }

    @Test
    void withoutDirectoryNothingIsReadBack() throws IOException {
        AuditAnchorStore store = new AuditAnchorStore((Path) null);
        assertFalse(store.isPersistent());
        store.append(anchor("node-a", 1));
        assertTrue(store.loadAll().isEmpty());
    }
}
