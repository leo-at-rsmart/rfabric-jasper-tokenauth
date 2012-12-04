package com.rsmart.rfabric.jasperreports.auth.listprovider;

import java.util.Map;

import org.springframework.security.GrantedAuthority;

import com.rsmart.rfabric.jasperreports.auth.ExternalUserProvider;

public class ListUserProvider implements ExternalUserProvider {
  private Map<String, User> users = null;
  
  public void setUsers(Map<String, User> users) {
    this.users = users;
  }
  
  public Map<String, User> getUsers() {
    return users;
  }
  
  public boolean userExists(String user) {
    return (users != null && users.containsKey(user));
  }

  public GrantedAuthority[] getAuthoritiesForUser(String user) {
    if (users == null || user == null)
      return null;
    
    final User userObj = users.get(user);
    
    // TODO Auto-generated method stub
    return null;
  }

}
