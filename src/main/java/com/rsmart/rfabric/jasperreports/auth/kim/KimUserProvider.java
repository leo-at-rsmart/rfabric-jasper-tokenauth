package com.rsmart.rfabric.jasperreports.auth.kim;

import org.springframework.security.GrantedAuthority;

import com.rsmart.rfabric.jasperreports.auth.ExternalUserProvider;

public class KimUserProvider implements ExternalUserProvider {

  public boolean userExists(String user) {
    // TODO Consult KIM to get the real answer
    return true;
  }

  @SuppressWarnings("serial")
  public GrantedAuthority[] getAuthoritiesForUser(String user) {
    // TODO Determine what roles the user should have based upon roles in KIM
    
    // for now this is just a mock implementaiton that gives the user admin role
    GrantedAuthority[] mockAuthorities = new GrantedAuthority[1];
    
    mockAuthorities[0] = new GrantedAuthority() {

      public int compareTo(Object o) {
        GrantedAuthority that = (GrantedAuthority)o;
        return getAuthority().compareTo(that.getAuthority());
      }

      public String getAuthority() {
        return "ROLE_ADMIN";
      }
      
    };
    return mockAuthorities;
  }

}
