package github.certvalidator.certvalidator.Services;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import org.springframework.stereotype.Service;

@Service 
public class CertValidationService {
    
    private PKIXParameters pkixParameters;
    CertPathValidator validator;

    public  CertValidationService(PKIXParameters pkixParameters, CertPathValidator validator) {
        this.pkixParameters = pkixParameters;
        this.validator = validator;
    }

    public PKIXCertPathValidatorResult validateCertificate(X509Certificate cert) throws NoSuchAlgorithmException, CertPathValidatorException, InvalidAlgorithmParameterException{
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(null, pkixParameters); // Is cert have the chain in it and if not how to build it and get the intermidaide ones til the root

            return result;
    }

}
