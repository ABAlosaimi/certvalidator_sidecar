package github.certvalidator.certvalidator.Config;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration 
public class CertValidationConfig {

    @Value("${keys.default.cacerts.password}")
    private String defaultCAcertsPassword;
    @Value("${cert.path.validation.algorithm}")
    private String pathValidationAlgorithm;
    @Value("${keys.default.keymanager.password}")
    private String keyManagerPw;
    @Value("${keys.default.keymanager.container.format}")
    private String keyManagerKeyStoreInstanceFormat;
    @Value("${cert.san.allow}")
    private List<String> sanAllowList;

    String tsPath = System.getenv("APP_TRUSTSTORE_PATH");
    String tsPassword = System.getenv("APP_TRUSTSTORE_PASSWORD");
    String tsType = System.getenv("APP_TRUSTSTORE_TYPE");
    
    // The path-based validation beans start
    @Bean 
    public PKIXParameters buildParams() throws Exception {
        KeyStore trustStore;

        if (tsPath != null) {
            // custome trust store init
            trustStore = KeyStore.getInstance(
                tsType != null ? tsType : KeyStore.getDefaultType()
            );
            char[] pw = tsPassword != null ? tsPassword.toCharArray() : null;
            try (InputStream is = Files.newInputStream(Paths.get(tsPath))) {
                trustStore.load(is, pw);
            }
        } else {
            // Fall back to JVM default cacerts
            String javaHome = System.getProperty("java.home");
            Path cacertsPath = Paths.get(javaHome, "lib", "security", "cacerts");
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

            try (InputStream is = Files.newInputStream(cacertsPath)) {
                trustStore.load(is, defaultCAcertsPassword.toCharArray());
            }
        }

        PKIXParameters params = new PKIXParameters(trustStore);
        // This will check about the env config and if the revocation is false (the env is "true") then the revocation will be enabled
        params.setRevocationEnabled(!"false".equalsIgnoreCase(System.getenv("APP_REVOCATION_ENABLED")));

        return params;
    }

    @Bean
    public CertPathValidator certPathValidator() throws NoSuchAlgorithmException {
         CertPathValidator certPathValidator = CertPathValidator.getInstance(pathValidationAlgorithm);

         return certPathValidator;
    }

    @Bean
    public CertificateFactory certificateFactory() throws CertificateException {
        return CertificateFactory.getInstance("X.509");
    }
    // The path-based validation beans end


    // The SSL (TLS) Context and engine start (javax)
    @Bean 
    public SSLContext sslContext() throws NoSuchAlgorithmException {
        return SSLContext.getInstance("TLS");
    }

    @Bean
    public KeyManager[] keyManager() throws Exception {
        char[] password = keyManagerPw.toCharArray();
        KeyStore ks = KeyStore.getInstance(keyManagerKeyStoreInstanceFormat);

        ks.load(new FileInputStream("sidecar-identity.p12"), password);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        kmf.init(ks, password);
        KeyManager[] keyManagers = kmf.getKeyManagers();

        return keyManagers;
    }
    // The SSL (TLS) Context and engine end (javax)

    // SANs allow list config start
    @Bean
    public List<String> sanAllow() {
        return this.sanAllowList;
    }
    // SANs allow list config end
}