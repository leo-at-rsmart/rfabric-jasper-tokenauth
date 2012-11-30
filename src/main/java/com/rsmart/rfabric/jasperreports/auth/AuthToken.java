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

import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.providers.AbstractAuthenticationToken;

/**
 * Utility class for dealing with authentication token semantics. 
 * Note: Class is thread safe.
 */
@SuppressWarnings("PMD.LongVariable")
public class AuthToken extends AbstractAuthenticationToken {
  private static final Log LOG = LogFactory.getLog(AuthToken.class);
  public static final String AUTH_TOKEN_HEADER = "x-authn-token";
  public static final String TOKEN_SEPARATOR = ":";

  protected transient Signature signature = new Signature();
  private transient final SecureRandom secureRandom = new SecureRandom();

  private transient String sharedSecret = null;
  private transient String token = null;
  private transient String claimedUserId = null;
  private transient String hash = null;
  private transient String nonce = null;
  private transient String validatedUserId = null;

  /**
   * Simply grab the authentication token from the request. Does not validate
   * results; i.e. raw data retrieval from request.
   * 
   * @param request
   * @return token
   * @throws IllegalArgumentException
   */
  public static final String getToken (final HttpServletRequest request) {
    LOG.debug("getToken(final HttpServletRequest request)");
    if (request == null) {
      throw new IllegalArgumentException("request == null");
    }
    return request.getHeader(AUTH_TOKEN_HEADER);    
  }
  
  /**
   */
  public AuthToken(final String sharedSecret, final String token) {
    LOG.debug("new AuthToken(****, " + token + ")");
    
    this.sharedSecret = sharedSecret;
    this.token = token;
    
    processToken();
  }
  
  public AuthToken(final String sharedSecret, final HttpServletRequest request) {
    this(sharedSecret, AuthToken.getToken(request));
  }

  /**
   * Reports whether the token is valid and hence whether the user name should be trusted.
   * 
   */
  public final boolean isValid() {
    return (validatedUserId != null);
  }
  
  /**
   * Returns the user ID the token wishes to authenticate.
   * 
   */
  public final String getClaimedUserId() {
    return claimedUserId;
  }

  /**
   * Returns the validated user ID if the token is valid. Returns null if the token is invalid
   * 
   */
  public final String getValidatedUserId() {
    return validatedUserId;
  }
  
  /**
   * Checks the validity of the token and sets the validatedUserId if the token passes.
   * 
   */
  private final void processToken() {
    LOG.debug("processToken()");
    if (token == null || "".equals(token)) {
      LOG.debug("token is null; setting user name to null");
      validatedUserId = null;
      return;
    }
    if (sharedSecret == null || "".equals(sharedSecret)) {
      LOG.error("sharedSecret is empty");
      throw new IllegalStateException("sharedSecret == null || empty");
    }

    if (token != null) {
      final String[] parts = token.split(TOKEN_SEPARATOR);
      if (parts.length == 3) {
        try {
          // collect parts of the token
          hash = parts[0];
          claimedUserId = parts[1];
          nonce = parts[2];
          
          LOG.debug("hash: " + hash + " claimedId: " + claimedUserId + " nonce: " + nonce);
          
          //validate the hash
          final String message = claimedUserId + TOKEN_SEPARATOR + nonce;
          final String hmac = signature.calculateRFC2104HMAC(message,
              sharedSecret);
          if (hmac.equals(hash)) {
            LOG.debug("token is valid");
            // the user is Ok, we will trust it.
            validatedUserId = claimedUserId;
          } else {
            LOG.warn("invalid token: " + token);
          }
        } catch (InvalidKeyException e) {
          LOG.error("Failed to validate server token: " + token, e);
        }
      } else {
        LOG.error("Illegal number of elements in trusted server token: "
            + token);
      }
    }
  }

  public Object getCredentials() {
    return getValidatedUserId();
  }

  public Object getPrincipal() {
    return getValidatedUserId();
  }
  
}