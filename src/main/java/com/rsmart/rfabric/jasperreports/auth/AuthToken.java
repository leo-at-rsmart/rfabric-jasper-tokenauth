package com.rsmart.rfabric.jasperreports.auth;

public class AuthToken {
  
  public static final String TOKEN_SEPARATOR = ":";

  private String token = null;
  private String hash = null;
  private String name = null;
  private String nonce = null;
  
  public AuthToken (final String token) {
    if (token == null || token.isEmpty()) {
      throw new IllegalArgumentException ("token is empty");
    }
    
    this.token = token;
    
    final String parts[] = token.split(TOKEN_SEPARATOR);
    if (parts == null || parts.length != 3) {
      throw new IllegalArgumentException ("malformed token");
    }
    
    hash = parts[0];
    name = parts[1];
    nonce = parts[2];
  }
  
  public String getHash() {
    return hash;
  }
  
  public String getName() {
    return name;
  }
  
  public String getNonce() {
    return nonce;
  }
  
  public String toString() {
    return token;
  }
}
