package org.keycloak.examples.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:alain.nguidjoi.bell@gmail.com"> Alain NGUIDJOI BELL</a>
 * @version $Revision: 1 $
 */
public class OtpSmsAuthenticator implements Authenticator, CredentialValidator<OtpSmsCredentialProvider> {

    private static final Logger logger = Logger.getLogger(OtpSmsAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (generateSaveAndSendCode(context)) {
            Response challenge = context.form()
                    .createForm("otp-code.ftl");
            context.challenge(challenge);
            return;
        }

        Response challenge = context.form()
                .setError("Unable to send sms code.")
                .createForm("otp-code.ftl");
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
    }

    private boolean generateSaveAndSendCode(AuthenticationFlowContext context) {
        String value = generateCode(context);
        saveCode(context, value);
        logger.info("Generated value is : " + value);
        return true;
    }

    private String generateCode(AuthenticationFlowContext context) {
        OTPPolicy otpPolicy = context.getRealm().getOTPPolicy();
        String value = "";
        if ("hotp".equals(otpPolicy.getType())) {
            HmacOTP generator = new HmacOTP(otpPolicy.getDigits(), otpPolicy.getAlgorithm(), otpPolicy.getLookAheadWindow());
            String secret = HmacOTP.generateSecret(13);
            value = generator.generateOTP(secret, "11", otpPolicy.getDigits(), otpPolicy.getAlgorithm());
        } else {
            TimeBasedOTP generator = new TimeBasedOTP(otpPolicy.getAlgorithm(), otpPolicy.getDigits(), otpPolicy.getPeriod(), otpPolicy.getLookAheadWindow());
            String secret = HmacOTP.generateSecret(13);
            value = generator.generateOTP(secret, "11", otpPolicy.getDigits(), otpPolicy.getAlgorithm());
        }
        return value;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("Beginning action ");
        boolean validated = validateCode(context);
        if (!validated) {
            Response challenge = context.form()
                    .setError("badSecret")
                    .createForm("otp-code.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }
        context.success();
    }

    protected boolean validateCode(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst("otp_value");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote("otpCode");

        if (code == null) {
            return false;
        }

        logger.info(" otpCode : "+code);
        return enteredCode.equals(code);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
        //getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {

    }

    @Override
    public OtpSmsCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (OtpSmsCredentialProvider) session.getProvider(CredentialProvider.class, OtpSmsCredentialProviderFactory.PROVIDER_ID);
    }

    public void saveCode(AuthenticationFlowContext context, String value) {

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote("otpCode", value);
       context.success();
    }
}
