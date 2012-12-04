package com.rsmart.rfabric.jasperreports.auth;

import static org.junit.Assert.*;

import java.security.SecureRandom;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.mockito.Mockito.*;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;

import com.rsmart.rfabric.jasperreports.auth.AuthToken;
import com.rsmart.rfabric.jasperreports.auth.AuthTokenAuthentication;
import com.rsmart.rfabric.jasperreports.auth.AuthTokenAuthenticationProvider;
import com.rsmart.rfabric.jasperreports.auth.ExternalUserProvider;
import com.rsmart.rfabric.jasperreports.auth.Signature;

@RunWith(MockitoJUnitRunner.class)
public class TestAuthTokenAuthenticationProvider {

  private static final String SECRET_KEY = "secret key";
  private static final String JOHNDOE = "jdoe@email.com";
  private static final String NOTAUSER = "nobody";
  private static final String MASTER_OF_THE_UNIVERSE = "Neil DeGrasse Tyson";
  
  private AuthTokenAuthenticationProvider authnProvider = new AuthTokenAuthenticationProvider();
  private Signature signature = new Signature();
  private SecureRandom secRand = new SecureRandom();
  
  @Mock
  private ExternalUserProvider userProvider;
  
  @Mock
  private GrantedAuthority authority;
  
  @Before
  public void createProvider() throws Exception {
    when(userProvider.userExists(JOHNDOE)).thenReturn(true);
    when(authority.getAuthority()).thenReturn(MASTER_OF_THE_UNIVERSE);
    when(userProvider.getAuthoritiesForUser(JOHNDOE)).thenReturn(new GrantedAuthority[] { authority });
    when(userProvider.userExists(NOTAUSER)).thenReturn(false);
    authnProvider.setExternalUserProvider(userProvider);
    authnProvider.setSecret(SECRET_KEY);
  }
  
  protected String generateToken (final String user) throws Exception {
    byte bytes[] = new byte[20];
    secRand.nextBytes(bytes);
    
    final String nonce = new String(bytes);
    final String toSign = user + AuthToken.TOKEN_SEPARATOR + nonce;
    final String hmac = signature.calculateRFC2104HMACWithEncoding(toSign, SECRET_KEY, true);
    
    return hmac + AuthToken.TOKEN_SEPARATOR + toSign;
  }
  
  @Test
  public void testAuthenticateValidToken() throws Exception {
    final String token = generateToken(JOHNDOE);
    
    AuthToken authToken = new AuthToken(token);
    AuthTokenAuthentication authentication = new AuthTokenAuthentication(authToken);
    
    Authentication result = authnProvider.authenticate(authentication);
    
    assertTrue(result.isAuthenticated());
    assertEquals(result.getName(), JOHNDOE);
    assertEquals(result.getPrincipal(), JOHNDOE);
    
    GrantedAuthority authorities[] = result.getAuthorities();
    
    assertNotNull(authorities);
    assertEquals(authorities[0].getAuthority(), MASTER_OF_THE_UNIVERSE);
  }

  @Test
  public void testAuthenticateInvalidToken() throws Exception {
    final String token = generateToken(NOTAUSER);
    
    AuthToken authToken = new AuthToken(token);
    AuthTokenAuthentication authentication = new AuthTokenAuthentication(authToken);
    
    Authentication result = authnProvider.authenticate(authentication);
    
    assertFalse(result.isAuthenticated());
    assertNull(result.getName());
    assertNull(result.getPrincipal());
    
    GrantedAuthority authorities[] = result.getAuthorities();
    
    assertNull(authorities);
  }
}
