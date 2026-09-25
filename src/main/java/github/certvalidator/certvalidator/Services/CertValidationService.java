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
import java.util.Collection;
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
    private List<String> sanAllowList;

    public  CertValidationService(PKIXParameters pkixParameters, CertPathValidator validator, SSLContext ctx, KeyManager[] keyManagers, CertificateFactory cf, List<String> sanAllowList) {
        this.pkixParameters = pkixParameters;
        this.validator = validator;
        this.ctx = ctx;
        this.keyManagers = keyManagers;
        this.cf = cf;
        this.sanAllowList = sanAllowList;
    }

    // should be refactored to retrun the end result not the path result cuz we are doing 4 diff checks on the certs
    public PKIXCertPathValidatorResult validateCertificate(X509Certificate[] chain) throws NoSuchAlgorithmException, CertPathValidatorException, InvalidAlgorithmParameterException, InvalidCertificateException, CertificateException {
        
        // Self signing validation
        X509Certificate leafCert = chain[0];

        if (leafCert.getSubjectX500Principal().equals(leafCert.getIssuerX500Principal())) {
            throw new InvalidCertificateException("Invalid Certificate: SELF_SIGNED_CERTIFICATE");
        }

        // SANs validation
        Collection<List<?>> sans = leafCert.getSubjectAlternativeNames();
        if (sans != null) {
            for (List<?> entry : sans) { // 2 = DNS name, 7 = IP address
                Integer type = (Integer) entry.get(0); 
                String  value = (String) entry.get(1);

                if (type.intValue() == 2) {
                    if (!value.equals(sanAllowList.get(0))) {
                        throw new CertificateException("The certificate domain should not talk to this app");
                    }
                }

                if (type.intValue() == 7) {
                    if (!value.equals(sanAllowList.get(1))) {
                        throw new CertificateException("The certificate IP should not talk to this app");
                    }
                }
            }   
        } else {
            throw new CertificateException("The cert do not have SAN");
        }

        
        // EKU and KU validation (we use here the OID to validate if the key is can be used for client validation which technically named id-kp-clientAuth)
        boolean[] ku = leafCert.getKeyUsage();

        if (!ku[0]) {
            throw new CertificateException("The certificate properities not appliacle for this application");
        }
        
        List<String> eku = leafCert.getExtendedKeyUsage();

        boolean clientAuth = eku != null && eku.contains("1.3.6.1.5.5.7.3.2"); // id-kp-clientAuth 
        if (!clientAuth) {
            throw new InvalidCertificateException("Invalid Certificate: EKU_NOT_CLIENT_AUTH");
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
                                    } catch (Exception e) {
                                        throw new CertificateException("certificate not valid for this application");    
                                    }     
                                 }

                                // update these later either to throw or delegate to the same validation method
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
