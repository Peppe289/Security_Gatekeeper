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
        jdbc.sql("INSERT INTO routes (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?)")
                .params(p.getPrefix(), p.getTargetUrl(), p.isEnabled(), p.getApiKeyHash(),
                        p.getBurstCapacity(), p.getRefillPerSecond())
                .update();
    }

    /** @return {@code true} if inserted, {@code false} if the prefix already existed */
    public boolean insertIfAbsent(RoutePolicy p) {
        return jdbc.sql("INSERT INTO routes (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (prefix) DO NOTHING")
                .params(p.getPrefix(), p.getTargetUrl(), p.isEnabled(), p.getApiKeyHash(),
                        p.getBurstCapacity(), p.getRefillPerSecond())
                .update() == 1;
    }

    /** @return {@code true} if a row was updated */
    public boolean update(RoutePolicy p) {
        return jdbc.sql("""
                        UPDATE routes SET target_url = ?, enabled = ?, api_key_hash = ?,
                               burst_capacity = ?, refill_per_second = ?, updated_at = now()
                        WHERE prefix = ?""")
                .params(p.getTargetUrl(), p.isEnabled(), p.getApiKeyHash(),
                        p.getBurstCapacity(), p.getRefillPerSecond(), p.getPrefix())
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
