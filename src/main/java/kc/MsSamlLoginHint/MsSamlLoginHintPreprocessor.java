package kc.MsSamlLoginHint;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.KeycloakSessionUtil;

public class MsSamlLoginHintPreprocessor implements SamlAuthenticationPreprocessor {

    private static final Logger LOG = Logger.getLogger(MsSamlLoginHintPreprocessor.class);

    private final KeycloakSession session;

    public MsSamlLoginHintPreprocessor() {
        this.session = null;
    }

    public MsSamlLoginHintPreprocessor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public SamlAuthenticationPreprocessor create(KeycloakSession session) {
        return new MsSamlLoginHintPreprocessor(session);
    }

    @Override
    public AuthnRequestType beforeProcessingLoginRequest(
            AuthnRequestType authnRequest,
            AuthenticationSessionModel authSession) {

        // SamlSessionUtils invokes the ProviderFactory singleton directly without calling create(session),
        // so we fetch the current thread's KeycloakSession via KeycloakSessionUtil.
        KeycloakSession currentSession = (this.session != null)
                ? this.session
                : KeycloakSessionUtil.getKeycloakSession();

        if (currentSession == null || authSession == null) {
            LOG.warnf("MsSamlLoginHintPreprocessor: currentSession (%s) or authSession (%s) is null",
                    currentSession, authSession);
            return authnRequest;
        }

        KeycloakContext context = currentSession.getContext();
        if (context == null || context.getHttpRequest() == null) {
            LOG.warn("MsSamlLoginHintPreprocessor: KeycloakContext or HttpRequest is null");
            return authnRequest;
        }

        HttpRequest req = context.getHttpRequest();
        String username = null;

        // 1. Check URL Query Parameters (?username=... or ?login_hint=...)
        if (req.getUri() != null) {
            MultivaluedMap<String, String> queryParams = req.getUri().getQueryParameters();
            if (queryParams != null) {
                if (queryParams.containsKey("username")) {
                    username = queryParams.getFirst("username");
                } else if (queryParams.containsKey("login_hint")) {
                    username = queryParams.getFirst("login_hint");
                }
            }
        }

        // 2. Fallback: Check POST Form Body Parameters
        if (username == null || username.isBlank()) {
            try {
                MultivaluedMap<String, String> formParams = req.getDecodedFormParameters();
                if (formParams != null) {
                    if (formParams.containsKey("username")) {
                        username = formParams.getFirst("username");
                    } else if (formParams.containsKey("login_hint")) {
                        username = formParams.getFirst("login_hint");
                    }
                }
            } catch (Exception ignored) {
                // Ignore if GET request or no form body
            }
        }

        // 3. Apply login_hint to AuthenticationSession and SAML AuthnRequest Subject
        if (username != null && !username.isBlank()) {
            username = username.trim();
            LOG.debugf("MsSamlLoginHintPreprocessor: Extracted login_hint '%s' for client '%s'",
                    username, authSession.getClient().getClientId());

            authSession.setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, username);
            authSession.setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

            if (authnRequest != null && authnRequest.getSubject() == null) {
                NameIDType nameId = new NameIDType();
                nameId.setValue(username);

                SubjectType subject = new SubjectType();
                SubjectType.STSubType subType = new SubjectType.STSubType();
                subType.addBaseID(nameId);
                subject.setSubType(subType);

                authnRequest.setSubject(subject);
            }
        } else {
            LOG.debugf("MsSamlLoginHintPreprocessor: No 'username' parameter found on SAML request to %s",
                    req.getUri() != null ? req.getUri().getRequestUri() : "unknown URI");
        }

        return authnRequest;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "ms-saml-login-hint-preprocessor";
    }
}
