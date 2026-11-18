package io.github.peppe289.security_gatekeeper.support;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;

/**
 * Full application on a random port, backed by a real PostgreSQL container.
 * All test classes share the same configuration, hence one cached Spring
 * context and one database container for the whole run.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gateway.node-id=test-node",
        "gateway.admin.password=" + IntegrationTest.ADMIN_PASSWORD,
        "gateway.audit.flush-interval=20ms",
        "gateway.dashboard.verify-cooldown=0s",
        "gateway.login-throttle.max-failures=3",
        "gateway.login-throttle.recovery=1h",
        "gateway.forwarder.response-timeout=3s"
})
@AutoConfigureMockMvc
@Import(TestcontainersConfig.class)
public @interface IntegrationTest {

    String ADMIN_PASSWORD = "test-admin-password";
}
