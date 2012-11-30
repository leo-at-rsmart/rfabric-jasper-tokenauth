/**
 * 
 * Modified from source found at:
 *  https://source.sakaiproject.org/svn/hybrid/trunk/sakai-hybrid-util/src/java/org/sakaiproject/hybrid/util/XSakaiToken.java
 *  
 * Licensed to the Sakai Foundation (SF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The SF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.rsmart.rfabric.jasperreports.auth;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;

/**
 * Utility class for dealing with authentication token semantics. 
 * Note: Class is thread safe.
 */
public class AuthTokenAuthentication implements Authentication{

  private static final long serialVersionUID = 3812168356075957938L;

  private static final Log LOG = LogFactory.getLog(AuthTokenAuthentication.class);

  protected transient Signature             signature = new Signature();
  protected transient AuthToken             authToken = null;
  protected transient String                name = null;
  protected transient GrantedAuthority[]    authorities = null;

  public AuthTokenAuthentication(final AuthToken token) {
    LOG.debug("new AuthToken(****, " + token + ")");
    
    this.authToken = token;
  }

  /**
   * Reports whether the token is valid and hence whether the user name should be trusted.
   * 
   */
  public final boolean isAuthenticated() {
    return (name != null);
  }
  
  /**
   * Returns the validated user ID if the token is valid. Returns null if the token is invalid
   * 
   */
  public final String getName() {
    return name;
  }
  
  final void setName(String name) {
    this.name = name;
  }

  @SuppressWarnings("serial")
  public GrantedAuthority[] getAuthorities() {
    
    if (authorities != null) {
      return authorities;
    }
    
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
  
  void setAuthorities(final GrantedAuthority authorities[]) {
    this.authorities = authorities;
  }

  public Object getCredentials() {
    return authToken;
  }

  public Object getDetails() {
    // TODO Auto-generated method stub
    return null;
  }

  public Object getPrincipal() {
    return getName();
  }


  public void setAuthenticated(boolean authenticated) throws IllegalArgumentException {
    if (authenticated) {
      LOG.error ("Illegal attempt to set status to authenticated externally");
      throw new IllegalArgumentException ("Cannot set authenticated to true externally");
    }
    
    name = null;
  }
}