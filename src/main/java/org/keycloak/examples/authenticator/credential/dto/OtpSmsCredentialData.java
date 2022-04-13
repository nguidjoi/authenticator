package org.keycloak.examples.authenticator.credential.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author <a href="mailto:alain.nguidjoi.bell@gmail.com"> Alain NGUIDJOI BELL</a>
 * @version $Revision: 1 $
 */
public class OtpSmsCredentialData {

    private final String otpCode;

    @JsonCreator
    public OtpSmsCredentialData(@JsonProperty("otpCode") String question) {
        this.otpCode = question;
    }

    public String getOtpCode() {
        return this.otpCode;
    }
}
