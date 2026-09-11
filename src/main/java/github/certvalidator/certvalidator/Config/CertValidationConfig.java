package github.certvalidator.certvalidator.Config;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.PKIXParameters;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration 
public class CertValidationConfig {
    
    @Bean 
    public PKIXParameters buildParams() throws Exception {
        String tsPath = System.getenv("APP_TRUSTSTORE_PATH");
        String tsPassword = System.getenv("APP_TRUSTSTORE_PASSWORD");
        String tsType = System.getenv("APP_TRUSTSTORE_TYPE");

        KeyStore trustStore;

        if (tsPath != null) {
            // custome trust store init
            trustStore = KeyStore.getInstance(
                tsType != null ? tsType : KeyStore.getDefaultType()
            );
            char[] pwd = tsPassword != null ? tsPassword.toCharArray() : null;
            try (InputStream is = Files.newInputStream(Paths.get(tsPath))) {
                trustStore.load(is, pwd);
            }
        } else {
            // Fall back to JVM default cacerts
            String javaHome = System.getProperty("java.home");
            Path cacertsPath = Paths.get(javaHome, "lib", "security", "cacerts");
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream is = Files.newInputStream(cacertsPath)) {
                trustStore.load(is, "changeit".toCharArray());
            }
        }

        PKIXParameters params = new PKIXParameters(trustStore);
        params.setRevocationEnabled(
            !"false".equalsIgnoreCase(System.getenv("APP_REVOCATION_ENABLED"))
        );

        return params;
    }
}