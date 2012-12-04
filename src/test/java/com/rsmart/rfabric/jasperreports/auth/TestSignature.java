package com.rsmart.rfabric.jasperreports.auth;

import static org.junit.Assert.*;
import org.junit.Test;

public class TestSignature {

  protected final static String SECRET = "secret key";
  protected final static String NONCE = "nonce";
  protected final static String USER = "user";
  
  protected final static String 
    BONAFIDE_AND_TESTED_CORRECT_RESULT = "Mjg4NzhhNzMzNjJhZjMwOTU5M2UyMmM0Y2E4ZGEzNWI3NTAyODdlOA";
  
  @Test
  public void testSignature() throws Exception {
    final String token = USER + ";" + NONCE;
    final Signature signature = new Signature();
    
    assertEquals(BONAFIDE_AND_TESTED_CORRECT_RESULT, 
       signature.calculateRFC2104HMACWithEncoding(token, SECRET, true));
  }
}
