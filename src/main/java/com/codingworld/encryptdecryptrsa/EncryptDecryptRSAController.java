
package com.codingworld.encryptdecryptrsa;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.function.EntityResponse;

@RestController
public class EncryptDecryptRSAController {

  @Autowired

  EncryptDecryptService encryptDecryptService;

  @GetMapping("/createKeys")
  public void createPrivatePublickey() {
    encryptDecryptService.createKeys();
  }

  @PostMapping("/encrypt")
  public String encryptMessage(@RequestBody String plainString) {
    return encryptDecryptService.encryptMessage(plainString);
  }


  @PostMapping("/decrypt")
  public String decryptMessage(@RequestBody String encryptString) {
    return encryptDecryptService.decryptMessage(encryptString);
  }

  @PostMapping("/encryptsharsa")
  public String encryptMessageSHARSA(@RequestBody String plainString) {
    return encryptDecryptService.sellarDigitalSHARSA(plainString);
  }


  @PostMapping("/decryptsharsa")
  public String decryptMessageSHARSA(@RequestBody String encryptString) {
    return encryptDecryptService.verificarSelloSHARSA(encryptString);
  }

}
