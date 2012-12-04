package com.rsmart.rfabric.jasperreports.auth.listprovider;

import org.springframework.security.GrantedAuthority;

public class Role implements GrantedAuthority {
  protected String role;
  
  public void setRoleName (final String name) {
    role = name;
  }
  
  public String getRoleName() {
    return role;
  }

  public int compareTo(Object o) {
    return this.getRoleName().compareTo(((Role)o).getRoleName());
  }

  public String getAuthority() {
    return role;
  }
  
}
