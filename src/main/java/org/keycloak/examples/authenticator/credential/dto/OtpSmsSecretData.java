package org.keycloak.examples.authenticator.credential.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author <a href="mailto:alain.nguidjoi.bell@gmail.com"> Alain NGUIDJOI BELL</a>
 * @version $Revision: 1 $
 */
public class OtpSmsSecretData {

     private final String otpValue;

    @JsonCreator
     public OtpSmsSecretData(@JsonProperty("otpValue") String otpValue) {
         this.otpValue = otpValue;
     }

    public String getOtpValue() {
        return otpValue;
    }
}
