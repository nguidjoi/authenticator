package org.keycloak.examples.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.examples.authenticator.credential.OtpSmsCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;

/**
 * @author <a href="mailto:alain.nguidjoi.bell@gmail.com"> Alain NGUIDJOI BELL</a>
 * @version $Revision: 1 $
 */
public class OtpSmsCredentialProvider implements CredentialProvider<OtpSmsCredentialModel>, CredentialInputValidator {
    private static final Logger logger = Logger.getLogger(OtpSmsCredentialProvider.class);

    protected KeycloakSession session;

    public OtpSmsCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    private UserCredentialStore getCredentialStore() {
        return session.userCredentialManager();
    }


    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) {
            logger.info("Expected instance of UserCredentialModel for CredentialInput");
            return false;
        }
        if (!input.getType().equals(getType())) {
            logger.info("input.getType() : "+input.getType());
            logger.info("getType() : "+getType());
            return false;
        }
        String challengeResponse = input.getChallengeResponse();

        logger.info("input.getChallengeResponse() : "+challengeResponse);
        if (challengeResponse == null) {
            return false;
        }
        CredentialModel credentialModel = getCredentialStore().getStoredCredentialById(realm, user, input.getCredentialId());
        OtpSmsCredentialModel sqcm = getCredentialFromModel(credentialModel);
        logger.info("sqcm.getSecretQuestionSecretData().getOtpValue() : "+sqcm.getOtpSmsSecretData().getOtpValue());
        return sqcm.getOtpSmsSecretData().getOtpValue().equals(challengeResponse);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) return false;
        return getCredentialStore().getStoredCredentialsByTypeStream(realm, user, credentialType).count() > 0;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, OtpSmsCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        return getCredentialStore().createCredential(realm, user, credentialModel);
    }


    public void updateCredential(RealmModel realm, UserModel user, OtpSmsCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
         getCredentialStore().updateCredential(realm, user, credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return getCredentialStore().removeStoredCredential(realm, user, credentialId);
    }

    @Override
    public OtpSmsCredentialModel getCredentialFromModel(CredentialModel model) {
        return OtpSmsCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName(OtpSmsCredentialProviderFactory.PROVIDER_ID)
                .helpText("otp-sms-code")
                .createAction(OtpSmsAuthenticatorFactory.PROVIDER_ID)
                .removeable(false)
                .build(session);
    }

    @Override
    public String getType() {
        return OtpSmsCredentialModel.TYPE;
    }
}
