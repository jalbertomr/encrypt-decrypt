package com.codingworld.encryptdecryptrsa;

import com.fasterxml.jackson.databind.ser.Serializers.Base;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

@Service
public class EncryptDecryptService {

  public static Map<String, Object> map = new HashMap<>();

  public void createKeys() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(4096);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      PublicKey publicKey = keyPair.getPublic();
      PrivateKey privateKey = keyPair.getPrivate();
      map.put("publicKey", publicKey);
      map.put("privateKey", privateKey);
      System.out.println("Llave publica,privada creadas.");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public String encryptMessage(String plainText) {

    try {
    	
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");	
      //Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWITHSHA-256ANDMGF1PADDING");
      //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      PublicKey publicKey = (PublicKey) map.get("publicKey");
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] encrypt = cipher.doFinal(plainText.getBytes());
      return new String(Base64.getEncoder().encodeToString(encrypt));
    } catch (Exception e) {
    	e.printStackTrace();
    }
    return "";
  }

  public String decryptMessage(String encryptedMessage) {

	  
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
      //Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWITHSHA-256ANDMGF1PADDING");
      //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      PrivateKey privateKey = (PrivateKey) map.get("privateKey");
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      byte[] decrypt = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
      return new String(decrypt);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return "";
  }
  
  public String sellarDigitalSHARSA(String plainText) {

	    try {
	    	Security.addProvider(new BouncyCastleProvider());
	    	
	      //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");	
	      Signature pss = Signature.getInstance("SHA256withRSAandMGF1");
	      
	      //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	      //PublicKey publicKey = (PublicKey) map.get("publicKey");
	      PrivateKey privateKey = (PrivateKey) map.get("privateKey");
	      pss.initSign(privateKey);
	      //byte[] encrypt = pss.getEncoded(plainText);
	      byte[] arrBytePaintText = plainText.getBytes();
	      pss.update(arrBytePaintText);
	      pss.sign();
	      return new String(Base64.getEncoder().encodeToString(arrBytePaintText));
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return "";
	  }

	  public String verificarSelloSHARSA(String encryptedMessage) {

	    try {
	      //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
	      Cipher cipher = Cipher.getInstance("SHA256withRSAandMGF1");
	      //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	      PrivateKey privateKey = (PrivateKey) map.get("privateKey");
	      cipher.init(Cipher.DECRYPT_MODE, privateKey);
	      byte[] decrypt = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
	      return new String(decrypt);
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	    return "";
	  }
	  
  /*
   * Security.addProvider(new BouncyCastleProvider());
   * import org.bouncycatle.jce.provider.BouncyCastleProvider;
   * <dependency>
   *   <groupid>org.bouncycastle</groupId>
   *   <artifactId>bcprov-jdk15on</artifactId>
   * </dependency>
   * Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
   * Signature pss = Signature.getInstance("SHA256withRSAandMGF1");
   * 
   */
   
}
