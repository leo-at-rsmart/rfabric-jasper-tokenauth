package com.rsmart.rfabric.jasperreports.auth;

import org.springframework.security.GrantedAuthority;

public interface ExternalUserProvider {
  public boolean userExists(String user);
  
  public GrantedAuthority[] getAuthoritiesForUser(String user);
}
