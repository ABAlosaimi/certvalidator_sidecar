package github.certvalidator.certvalidator.Services;

import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.springframework.stereotype.Service;
import github.certvalidator.certvalidator.Exceptions.InvalidCertificateException;

@Service 
public class CertValidationService {
    
    private PKIXParameters pkixParameters;
    private CertPathValidator validator;
    private SSLContext ctx;
    private KeyManager[] keyManagers;
    private CertificateFactory cf;


    public  CertValidationService(PKIXParameters pkixParameters, CertPathValidator validator, SSLContext ctx, KeyManager[] keyManagers, CertificateFactory cf) {
        this.pkixParameters = pkixParameters;
        this.validator = validator;
        this.ctx = ctx;
        this.keyManagers = keyManagers;
        this.cf = cf;
    }

    // should be refactored to retrun the end result not the path result 
    public PKIXCertPathValidatorResult validateCertificate(X509Certificate[] chain) throws NoSuchAlgorithmException, CertPathValidatorException, InvalidAlgorithmParameterException, InvalidCertificateException, CertificateException {
        
        // Self signing validation
        X509Certificate leafCert = chain[0];

        if (leafCert.getSubjectX500Principal() == leafCert.getIssuerX500Principal()) {
            throw new InvalidCertificateException("Invalid Certificate: SELF_SIGNED_CERTIFICATE");   
        }

        // Temporal validation
        leafCert.checkValidity();

        // Cert path validation
        CertPath certPath = cf.generateCertPath(List.of(chain));
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, pkixParameters);

        return result;
    }


    public void extractLeafCertificate() throws Exception {
        ctx.init(keyManagers, new TrustManager[] {
                 new X509ExtendedTrustManager() {
                                 @Override
                                 public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                                   try{
                                     validateCertificate(chain); // should throws CertificateException to abort handshake if one of the conditions aren't met
                                    } catch (Exception e) {}     
                                  }

                                 @Override
                                 public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

                                 @Override
                                 public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

                                 @Override
                                 public X509Certificate[] getAcceptedIssuers() {return null;}

                                 @Override
                                 public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {}

                                 @Override
                                 public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {}

                                 @Override
                                 public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {}
        
                }
        }, null);

        SSLEngine engine = ctx.createSSLEngine();
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(true);
    }

}
