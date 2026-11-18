package io.github.peppe289.security_gatekeeper.audit;

import io.github.peppe289.security_gatekeeper.core.audit.AuditRecord;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * JDBC access to the append-only {@code audit_log} table.
 */
@Repository
public class AuditRepository {

    private static final String COLUMNS = "sequence, ts, client_ip, method, path, route_prefix, decision, "
            + "http_status, previous_hash, hash";
    private static final int STREAM_FETCH_SIZE = 1000;

    private final JdbcClient jdbc;
    private final JdbcTemplate jdbcTemplate;
    private final TransactionTemplate readOnlyTx;
    private final TransactionTemplate tx;

    /** A persisted record together with the node that wrote it. */
    public record StoredRecord(String nodeId, AuditRecord record) {

        public Instant timestamp() {
            return Instant.ofEpochMilli(record.getTimestampMillis());
        }
    }

    /** Last record of a node's chain, used to resume it. */
    public record ChainHead(long lastSequence, String lastHash) {
    }

    public AuditRepository(JdbcClient jdbc, JdbcTemplate jdbcTemplate, TransactionTemplate transactionTemplate) {
        this.jdbc = jdbc;
        this.jdbcTemplate = jdbcTemplate;
        this.tx = transactionTemplate;
        this.readOnlyTx = new TransactionTemplate(transactionTemplate.getTransactionManager());
        this.readOnlyTx.setReadOnly(true);
    }

    public Optional<ChainHead> findHead(String nodeId) {
        return jdbc.sql("SELECT sequence, hash FROM audit_log WHERE node_id = ? ORDER BY sequence DESC LIMIT 1")
                .param(nodeId)
                .query((rs, i) -> new ChainHead(rs.getLong("sequence"), rs.getString("hash")))
                .optional();
    }

    /** @return {@code true} if {@code record} (same sequence and hash) is stored for {@code nodeId} */
    public boolean contains(String nodeId, AuditRecord record) {
        return jdbc.sql("SELECT EXISTS (SELECT 1 FROM audit_log WHERE node_id = ? AND sequence = ? AND hash = ?)")
                .params(nodeId, record.getSequence(), record.getHash())
                .query(Boolean.class)
                .single();
    }

    /** Inserts a batch atomically: either every record is stored or none is. */
    public void insertBatch(String nodeId, List<AuditRecord> records) {
        tx.executeWithoutResult(status -> jdbcTemplate.batchUpdate(
                "INSERT INTO audit_log (node_id, " + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                records, records.size(), (ps, r) -> {
                    ps.setString(1, nodeId);
                    ps.setLong(2, r.getSequence());
                    ps.setTimestamp(3, Timestamp.from(Instant.ofEpochMilli(r.getTimestampMillis())));
                    ps.setString(4, r.getClientIp());
                    ps.setString(5, r.getMethod());
                    ps.setString(6, r.getPath());
                    ps.setString(7, r.getRoutePrefix());
                    ps.setString(8, r.getDecision());
                    ps.setInt(9, r.getHttpStatus());
                    ps.setString(10, r.getPreviousHash());
                    ps.setString(11, r.getHash());
                }));
    }

    /** @return the newest records across all nodes, newest first */
    public List<StoredRecord> findLatest(int limit) {
        return jdbc.sql("SELECT node_id, " + COLUMNS + " FROM audit_log ORDER BY ts DESC, sequence DESC LIMIT ?")
                .param(limit)
                .query((rs, i) -> new StoredRecord(rs.getString("node_id"), map(rs)))
                .list();
    }

    public List<String> findNodeIds() {
        return jdbc.sql("SELECT DISTINCT node_id FROM audit_log ORDER BY node_id").query(String.class).list();
    }

    /**
     * Streams a node's chain in sequence order through {@code consumer} with a
     * server-side cursor (constant memory). Stops when the consumer returns {@code false}.
     */
    public void streamChain(String nodeId, Predicate<AuditRecord> consumer) {
        readOnlyTx.executeWithoutResult(status -> jdbcTemplate.query(con -> {
            var ps = con.prepareStatement("SELECT " + COLUMNS + " FROM audit_log WHERE node_id = ? ORDER BY sequence");
            ps.setFetchSize(STREAM_FETCH_SIZE);
            ps.setString(1, nodeId);
            return ps;
        }, rs -> {
            boolean more = true;
            while (more && rs.next()) {
                more = consumer.test(map(rs));
            }
            return null;
        }));
    }

    private static AuditRecord map(ResultSet rs) throws SQLException {
        return new AuditRecord(
                rs.getLong("sequence"),
                rs.getObject("ts", OffsetDateTime.class).toInstant().toEpochMilli(),
                rs.getString("client_ip"),
                rs.getString("method"),
                rs.getString("path"),
                rs.getString("route_prefix"),
                rs.getString("decision"),
                rs.getInt("http_status"),
                rs.getString("previous_hash"),
                rs.getString("hash"));
    }
}
