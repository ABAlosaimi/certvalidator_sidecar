package github.certvalidator.certvalidator.Exceptions;

import java.security.cert.CertificateException;

public class InvalidCertificateException extends CertificateException {
    
    public InvalidCertificateException(String msg){
        super(msg);
    }

}
