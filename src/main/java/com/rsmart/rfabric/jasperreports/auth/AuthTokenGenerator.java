package com.rsmart.rfabric.jasperreports.auth;

import java.security.InvalidKeyException;
import java.security.SecureRandom;

public class AuthTokenGenerator {

  /**
   * @param args
   */
  public static void main(String[] args) {
    if (args.length < 2) {
      System.out.println("Usage:\n\tjava " + AuthTokenGenerator.class.getName() + " <shared secret> <user>");
      System.exit(1);
    }
    if (args.length > 2) {
      System.err.println ("Extra command line arguments ignored");
    }
    
    final String secret = args[0];
    final String user = args[1];
    
    final Signature signature = new Signature();
    final SecureRandom rand = new SecureRandom();
    final int nonce = rand.nextInt();
    final String toSign = user + AuthToken.TOKEN_SEPARATOR + nonce;
    final String hmac;
    try {
      hmac = signature.calculateRFC2104HMACWithEncoding(toSign, secret, true);
      System.out.println (hmac + AuthToken.TOKEN_SEPARATOR + toSign);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      System.exit(0);
    }
    
  }

}
