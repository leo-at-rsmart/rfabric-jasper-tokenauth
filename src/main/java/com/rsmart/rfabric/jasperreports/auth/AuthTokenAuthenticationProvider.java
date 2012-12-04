package com.rsmart.rfabric.jasperreports.auth;

import java.security.InvalidKeyException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.providers.AuthenticationProvider;

/**
 * Implements the AuthenticationProvider interface from the Spring Framework Security
 * specification to enable proxy authentication of a user to JasperReports Server by 
 * a client service using AuthTokens. This provider will analyze AuthTokenAuthentication 
 * objects to determine if they contain a valid AuthToken credential. Validation is 
 * accomplished by generating am HMAC from the name and the nonce contained in the 
 * AuthToken credential, using a secret key shared with the client service at configuration
 * time. If the generate HMAC equals the hash contained in the AuthToken the token is
 * deemed valid.
 * 
 * Next an ExternalUserProvider is checked to determine if the user name is recognized.
 * If so the same ExternalUserProvider is queried for GrantedAuthorities for that user.
 * GrantedAuthorities are simply role names recognized by the JasperReports Server which
 * the user fills.
 * 
 * 
 * client service
 * @author duffy
 *
 */
public class AuthTokenAuthenticationProvider implements AuthenticationProvider {
  private static final Log LOG = LogFactory.getLog(AuthTokenAuthenticationProvider.class);

  protected transient Signature signature = new Signature();
  protected transient String secret = null;
  protected transient ExternalUserProvider userProvider = null;
  
  public AuthTokenAuthenticationProvider () {}
  
  public AuthTokenAuthenticationProvider (final String secret) {
    this.secret = secret;
  }
  
  public void setSecret (final String secret) {
    this.secret = secret;
  }
  
  public void setExternalUserProvider (final ExternalUserProvider provider) {
    this.userProvider = provider;
  }
  
  public Authentication authenticate(final Authentication authn)
      throws AuthenticationException {
    
    if (!supports(authn.getClass()) || authn == null) {
      throw new IllegalArgumentException ("Expecting AuthTokenAuthentication object as argument");
    }

    final AuthTokenAuthentication authentication = (AuthTokenAuthentication) authn;
    
    if (authentication.isAuthenticated()) {
      return authentication;
    }
    
    final AuthToken authToken = (AuthToken) authentication.getCredentials();

    if (secret == null || "".equals(secret)) {
      LOG.error("sharedSecret is empty");
      throw new IllegalStateException("sharedSecret == null || empty");
    }

    final String name = authToken.getName();
    
    if (!userProvider.userExists(name)) {
      LOG.error("User does not exist for token " + authToken);
      authn.setAuthenticated(false);
      return authn;
    }
    
    try {
      //validate the hash
      final String message = name + AuthToken.TOKEN_SEPARATOR + authToken.getNonce();
      final String hmac = signature.calculateRFC2104HMACWithEncoding(message, secret, true);
      if (hmac.equals(authToken.getHash())) {
        LOG.debug("token is valid");
        // the user is Ok, we will trust it.
        authentication.setName(name);
        authentication.setAuthorities(userProvider.getAuthoritiesForUser(name));
        return authentication;
      } else {
        LOG.warn("invalid token: " + authToken);
      }
    } catch (InvalidKeyException ike) {
      LOG.error ("Failed to validate token: " + authToken, ike);
      throw new IllegalStateException ("Invalid key used for hashing", ike);
    }
    
    return null;
  }

  @SuppressWarnings("rawtypes")
  public boolean supports(Class authTokenClass) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("supports(\"" + authTokenClass.getName() + "\") reports: " +
          AuthTokenAuthentication.class.isAssignableFrom(authTokenClass));      
    }
    return (AuthTokenAuthentication.class.isAssignableFrom(authTokenClass));
  }

}
