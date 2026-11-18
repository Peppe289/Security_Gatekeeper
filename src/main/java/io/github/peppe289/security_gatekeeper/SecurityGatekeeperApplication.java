package io.github.peppe289.security_gatekeeper;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SecurityGatekeeperApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityGatekeeperApplication.class, args);
    }
}
