package com.rsmart.rfabric.jasperreports.auth;

import org.springframework.security.GrantedAuthority;

/**
 * Provides information about users for use in the authentication process.
 *
 */
public interface ExternalUserProvider {

  /**
   * Determines if the external service recognizes the given user name.
   * 
   * @param user
   * @return
   */
  public boolean userExists(String user) throws Exception;
  
  /**
   * Returns the roles filled by the given user.
   * 
   * @param user
   * @return
   */
  public GrantedAuthority[] getAuthoritiesForUser(String user);
}
