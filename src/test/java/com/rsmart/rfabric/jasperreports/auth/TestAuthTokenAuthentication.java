package com.rsmart.rfabric.jasperreports.auth;

import static org.junit.Assert.*;
import org.junit.Test;
import org.springframework.security.GrantedAuthority;

public class TestAuthTokenAuthentication {

  private static final String HASH = "bogus hash";
  private static final String USER = "jdoe@email.com";
  private static final String NONCE = "nonce";
  
  @Test
  public void testNoNameMeansNotAuthenticated() throws Exception {
    final AuthToken token = new AuthToken (
        HASH + AuthToken.TOKEN_SEPARATOR + USER + AuthToken.TOKEN_SEPARATOR + NONCE);
    final AuthTokenAuthentication authn = new AuthTokenAuthentication(token);

    assertFalse(authn.isAuthenticated());
  }
  
  @Test
  public void testSettingNameFlagsAuthenticationAsTrue() throws Exception {
    final AuthToken token = new AuthToken (
        HASH + AuthToken.TOKEN_SEPARATOR + USER + AuthToken.TOKEN_SEPARATOR + NONCE);
    final AuthTokenAuthentication authn = new AuthTokenAuthentication(token);

    authn.setName(USER);
    assertTrue(authn.isAuthenticated());
  }
  
  @Test
  public void testInvalidateAuthentication() throws Exception {
    final AuthToken token = new AuthToken (
        HASH + AuthToken.TOKEN_SEPARATOR + USER + AuthToken.TOKEN_SEPARATOR + NONCE);
    final AuthTokenAuthentication authn = new AuthTokenAuthentication(token);

    authn.setName(USER);
    authn.setAuthorities(new GrantedAuthority[5]);
    assertTrue(authn.isAuthenticated());
    
    authn.setAuthenticated(false);
    assertFalse(authn.isAuthenticated());
    assertNull(authn.getPrincipal());
    assertNull(authn.getName());
    assertNull(authn.getAuthorities());
  }
}
