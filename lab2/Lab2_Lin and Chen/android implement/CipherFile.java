package com.lab2.AndroidEncrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
 
 public class CipherFile{
 
   private SecretKey key;                 		  /* key used by encrypt/decrypt routines */
   private String Mode;              		  /* name of file to store clear text output.  encrypt routine takes this as input stream */
   private Cipher ecipher;
   private Cipher dcipher;
   byte[] buffer = new byte[1024];
   /*
    *  public CipherFile(SecretKey,String,String)
    *  @PARAMS:
    *  SecretKey key: key object to store in class variable key
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: EncryptFile object
    */
   
   public CipherFile(String algrithm, String mode, String initKey) throws Exception{
	 this.Mode = mode;
	 //index used for the size of IV
	 int index = 0;
	 String config = "1";
	 if (algrithm.equals("AES128")){
		 index = 16;
		 KeyGenerator generator = KeyGenerator.getInstance( "AES" );
	     generator.init(128,new SecureRandom(initKey.getBytes()));
	     key = generator.generateKey();
	     config = "AES/" + Mode + "/PKCS5Padding";
	 }else if (algrithm.equals("AES256")){
		 index = 16;
		 KeyGenerator generator = KeyGenerator.getInstance( "AES" );
	     generator.init(256,new SecureRandom(initKey.getBytes()));
	     key = generator.generateKey();
	     config = "AES/" + Mode + "/PKCS5Padding";
	 }else if (algrithm.equals("DES")){
		 index = 8;
		 DESKeySpec dks = new DESKeySpec(initKey.getBytes());   
		 SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");   
		 key = keyFactory.generateSecret(dks);
	     config = "DES/" + Mode + "/PKCS5Padding";
	 }else if (algrithm.equals("3DES")){
		 index = 8;
         DESedeKeySpec dks = new DESedeKeySpec(initKey.getBytes());   
         SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");   
         key = keyFactory.generateSecret(dks);  
		 config = "DESede/" + Mode + "/PKCS5Padding";
	 } 
     byte[] iv = createIV(index);
     AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
         
     try {
    	 
    	 ecipher = Cipher.getInstance(config);
    	 dcipher = Cipher.getInstance(config);
    	 ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
    	 dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
     } catch (java.security.InvalidAlgorithmParameterException e) {
     } catch (javax.crypto.NoSuchPaddingException e) {
     } catch (java.security.NoSuchAlgorithmException e) {
     } catch (java.security.InvalidKeyException e) {
     }
   }
   
   public void encrypt(InputStream fclear, OutputStream fcipher){
	   try{
		   fcipher = new CipherOutputStream(fcipher,ecipher);
		   int numRead = 0;
		   while((numRead = fclear.read(buffer)) >= 0){
			   fcipher.write(buffer,0,numRead);
		   }
		   fcipher.close();
	   }catch(IOException e){
	   }
   }
   
   public void decrypt(InputStream fcipher, OutputStream fdecipher ){
	   try{

		   fcipher = new CipherInputStream(fcipher,dcipher);
		   int numRead = 0;
		   while((numRead = fcipher.read(buffer)) >= 0){
			   fdecipher.write(buffer,0,numRead);
		   }
		   fdecipher.close();
	   }catch(IOException e){
	   }
   }
   
	private static byte[] createIV(int index) throws IOException
	{
		SecureRandom random = null;
		try
		{
			random = SecureRandom.getInstance("SHA1PRNG");
		}
		catch (NoSuchAlgorithmException e)
		{
			System.out.println("NoSuchAlgorithmException: " + e);
			System.exit(-1);
		}
		byte[] bIV = new byte[index];
		random.nextBytes(bIV);		
		return bIV;
	}

 }