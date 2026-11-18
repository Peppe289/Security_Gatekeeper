package io.github.peppe289.security_gatekeeper.route;

import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * JDBC access to the {@code routes} table. All statements are parameterized.
 */
@Repository
public class RouteRepository {

    private static final String COLUMNS =
            "prefix, target_url, enabled, api_key_hash, burst_capacity, refill_per_second";

    private final JdbcClient jdbc;

    public RouteRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public List<RoutePolicy> findAll() {
        return jdbc.sql("SELECT " + COLUMNS + " FROM routes ORDER BY prefix")
                .query(RouteRepository::map)
                .list();
    }

    /** @throws org.springframework.dao.DuplicateKeyException if the prefix exists */
    public void insert(RoutePolicy p) {
        insert(p, "");
    }

    /** @return {@code true} if inserted, {@code false} if the prefix already existed */
    public boolean insertIfAbsent(RoutePolicy p) {
        return insert(p, " ON CONFLICT (prefix) DO NOTHING") == 1;
    }

    private int insert(RoutePolicy p, String suffix) {
        return jdbc.sql("INSERT INTO routes (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?)" + suffix)
                .params(p.getPrefix(), p.getTargetUrl(), p.isEnabled(), p.getApiKeyHash(),
                        p.getBurstCapacity(), p.getRefillPerSecond())
                .update();
    }

    // Updates touch only the column being changed: rewriting the whole row from a (possibly
    // stale) cached policy would silently undo concurrent changes made on another instance,
    // e.g. bring back an API key that was just rotated or removed.

    /** @return {@code true} if a row was updated */
    public boolean updateEnabled(String prefix, boolean enabled) {
        return jdbc.sql("UPDATE routes SET enabled = ?, updated_at = now() WHERE prefix = ?")
                .params(enabled, prefix)
                .update() == 1;
    }

    /** @return {@code true} if a row was updated */
    public boolean updateApiKeyHash(String prefix, String apiKeyHash) {
        return jdbc.sql("UPDATE routes SET api_key_hash = ?, updated_at = now() WHERE prefix = ?")
                .params(apiKeyHash, prefix)
                .update() == 1;
    }

    /** @return {@code true} if a row was deleted */
    public boolean delete(String prefix) {
        return jdbc.sql("DELETE FROM routes WHERE prefix = ?").param(prefix).update() == 1;
    }

    private static RoutePolicy map(ResultSet rs, int row) throws SQLException {
        return new RoutePolicy(rs.getString("prefix"), rs.getString("target_url"), rs.getBoolean("enabled"),
                rs.getString("api_key_hash"), rs.getLong("burst_capacity"), rs.getLong("refill_per_second"));
    }
}
