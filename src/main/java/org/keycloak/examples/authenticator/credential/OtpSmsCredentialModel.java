package org.keycloak.examples.authenticator.credential;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.examples.authenticator.credential.dto.OtpSmsCredentialData;
import org.keycloak.examples.authenticator.credential.dto.OtpSmsSecretData;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

/**
 * @author <a href="mailto:alain.nguidjoi.bell@gmail.com"> Alain NGUIDJOI BELL</a>
 * @version $Revision: 1 $
 */
public class OtpSmsCredentialModel extends CredentialModel {
    public static final String TYPE = "OTP_SMS";

    private final OtpSmsCredentialData credentialData;
    private final OtpSmsSecretData secretData;

    private OtpSmsCredentialModel(OtpSmsCredentialData credentialData, OtpSmsSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    private OtpSmsCredentialModel(String otpCode, String otpValue) {
        credentialData = new OtpSmsCredentialData(otpCode);
        secretData = new OtpSmsSecretData(otpValue);
    }

    public static OtpSmsCredentialModel createOtpCredentialModel(String otpCode, String otpValue) {
        OtpSmsCredentialModel credentialModel = new OtpSmsCredentialModel(otpCode, otpValue);
        credentialModel.fillCredentialModelFields();
        return credentialModel;
    }

    public static OtpSmsCredentialModel createFromCredentialModel(CredentialModel credentialModel){
        try {
            OtpSmsCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), OtpSmsCredentialData.class);
            OtpSmsSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), OtpSmsSecretData.class);

            OtpSmsCredentialModel secretQuestionCredentialModel = new OtpSmsCredentialModel(credentialData, secretData);
            secretQuestionCredentialModel.setUserLabel(credentialModel.getUserLabel());
            secretQuestionCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
            secretQuestionCredentialModel.setType(TYPE);
            secretQuestionCredentialModel.setId(credentialModel.getId());
            secretQuestionCredentialModel.setSecretData(credentialModel.getSecretData());
            secretQuestionCredentialModel.setCredentialData(credentialModel.getCredentialData());
            return secretQuestionCredentialModel;
        } catch (IOException e){
            throw new RuntimeException(e);
        }
    }

    public OtpSmsCredentialData getOtpSmsCredentialData() {
        return credentialData;
    }

    public OtpSmsSecretData getOtpSmsSecretData() {
        return secretData;
    }

    private void fillCredentialModelFields(){
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            setSecretData(JsonSerialization.writeValueAsString(secretData));
            setType(TYPE);
            setCreatedDate(Time.currentTimeMillis());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
