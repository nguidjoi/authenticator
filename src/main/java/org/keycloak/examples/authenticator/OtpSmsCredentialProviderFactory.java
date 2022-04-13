package org.keycloak.examples.authenticator;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

/**
 * @author <a href="mailto:alain.nguidjoi.bell@gmail.com"> Alain NGUIDJOI BELL</a>
 * @version $Revision: 1 $
 */
public class OtpSmsCredentialProviderFactory implements CredentialProviderFactory<OtpSmsCredentialProvider> {

    public static final String PROVIDER_ID =  "otp-sms";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new OtpSmsCredentialProvider(session);
    }
}
