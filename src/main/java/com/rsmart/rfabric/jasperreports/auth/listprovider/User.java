package com.rsmart.rfabric.jasperreports.auth.listprovider;

import java.util.List;

public class User {

  private String name;
  private List<Role> roles = null;
  
  public void setName(final String name) {
    this.name = name;
  }
  
  public String getName() {
    return name;
  }
  
  public void setRoles(List<Role> roles) {
    this.roles = roles;
  }
  
  public List<Role> getRoles() {
    return roles;
  }
}
