package com.rsmart.rfabric.jasperreports.auth;

import java.security.InvalidKeyException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.providers.AuthenticationProvider;

public class AuthTokenAuthenticationProvider implements AuthenticationProvider {
  private static final Log LOG = LogFactory.getLog(AuthTokenAuthenticationProvider.class);

  protected transient Signature signature = new Signature();
  protected transient String secret = null;
  
  public AuthTokenAuthenticationProvider () {}
  
  public AuthTokenAuthenticationProvider (final String secret) {
    this.secret = secret;
  }
  
  public void setSecret (final String secret) {
    this.secret = secret;
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

    try {
      //validate the hash
      final String message = authToken.getName() + AuthToken.TOKEN_SEPARATOR + authToken.getNonce();
      final String hmac = signature.calculateRFC2104HMAC(message, secret);
      if (hmac.equals(authToken.getHash())) {
        LOG.debug("token is valid");
        // the user is Ok, we will trust it.
        authentication.setName(authToken.getName());
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

  public boolean supports(Class authTokenClass) {
    return (AuthTokenAuthentication.class.isAssignableFrom(authTokenClass));
  }

}
