/*
 * AESEncryptFile.java
 * Lincoln Anderson
 * ELEC 5150
 * Spring 08
 * Lab 2 Part 1
 *
 */
 
 import java.io.*;
 import java.util.*;
 import java.security.*;
 import java.security.spec.*;

 import javax.crypto.*;
import javax.crypto.spec.*;
 
 public class AES256DecryptFile{
 
   private SecretKey key;                 		  /* key used by encrypt/decrypt routines */
   private String cipherAlgorithm = "AES";        /* Algorithm used for encrypt/decrypt, for example AES or AES(Rijndael) */
   private String clearText;              		  /* name of file to store clear text output.  encrypt routine takes this as input stream */
   private String cipherText;             		  /* name of file to store cipher text output.  decrypt routine takes this as input stream */
   private Cipher ecipher;
   private Cipher dcipher;
   byte[] buffer = new byte[1024];
   
   /*
    *  public AES256DecryptFile(String,String,String)
    *  @PARAMS:
    *  String initKey: key string to generate key
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: AES256DecryptFile object
    */
   
   public AES256DecryptFile(String initKey, String clearText, String cipherText) throws Exception{
	 //translate the key  
	 KeyGenerator generator = KeyGenerator.getInstance( "AES" );
     generator.init(256,new SecureRandom(initKey.getBytes()));
     key = generator.generateKey();
     this.clearText = clearText;
     this.cipherText = cipherText;
     // Create an 8-byte initialization vector
     byte[] iv = IVFromHex("IV.hex");
     AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
     try {
    	 ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	 dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	 // CBC requires an initialization vector
    	 ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
    	 dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
     } catch (java.security.InvalidAlgorithmParameterException e) {
     } catch (javax.crypto.NoSuchPaddingException e) {
     } catch (java.security.NoSuchAlgorithmException e) {
     } catch (java.security.InvalidKeyException e) {
     }
   }
   
   /*
    *  public AES256DecryptFile(SecretKey,String,String)
    *  @PARAMS:
    *  SecretKey key: key object to store in class variable key
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: AES256DecryptFile object
    */
   
   public AES256DecryptFile(SecretKey key, String clearText, String cipherText){
     this.key = key;
     this.clearText = clearText;
     this.cipherText = cipherText;
     try {
    	 ecipher = Cipher.getInstance("AES");
    	 dcipher = Cipher.getInstance("AES");
    	 ecipher.init(Cipher.ENCRYPT_MODE, key);
    	 dcipher.init(Cipher.DECRYPT_MODE, key); 
     } catch (java.security.InvalidKeyException e) {
     } catch (javax.crypto.NoSuchPaddingException e) {
     } catch (java.security.NoSuchAlgorithmException e) {
     } 
   }
   
   /*
    *  public AES256DecryptFile(String,String)
    *  @PARAMS:
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: AES256DecryptFile object with AES as default algorithm, creating a AES key
    */
 
   public AES256DecryptFile(String clearText, String cipherText){
     key = efKeyGenerator(cipherAlgorithm);
     this.clearText = clearText;
     this.cipherText = cipherText;
     try {
    	 ecipher = Cipher.getInstance("AES");
    	 dcipher = Cipher.getInstance("AES");
    	 // CBC requires an initialization vector
    	 ecipher.init(Cipher.ENCRYPT_MODE, key);
    	 dcipher.init(Cipher.DECRYPT_MODE, key); 
     } catch (java.security.InvalidKeyException e) {
     } catch (javax.crypto.NoSuchPaddingException e) {
     } catch (java.security.NoSuchAlgorithmException e) {
     } 
   }   
   
   /*
    *  public SecretKey efKeyGenerator(String)
    *  @PARAMS:
    *  String c: name of algorithm used to generate key.
    *  @OUTPUT:
    *    Returns: SecretKey key
    *    Creates: nothing.
    */
 
   public SecretKey efKeyGenerator(String c){
     try{
    	 KeyGenerator keyGen = KeyGenerator.getInstance(c);
    	 keyGen.init(128);
    	 SecretKey key = keyGen.generateKey();
		 return key;
     }catch(NoSuchAlgorithmException e){
     }
     return null;
   }
   
   /*
    *  public static void ToHEX(byte[], String)
    *  @PARAMS:
    *  byte[] text: the text need to be stored in Hex
    *  String String fileNam: name of the file
    *  @OUTPUT:
    *    Returns: noting
    *    Creates: hex file.
    */
   
   public static void ToHEX(byte[] text, String fileName) throws IOException{
		
	   String hexString = "";
		for(int i = 0; i < text.length; i++)
		{
			String hex = Integer.toHexString(text[i]&0xFF );
			if (hex.length() == 1) {
			    hex = "0" + hex;
			}
			hexString = hexString + hex;
		}         
	   FileOutputStream fos = new FileOutputStream(fileName);
	   fos.write(hexString.getBytes());
	   fos.close();
   }
 
   /*
    *  private static byte[] createIV()
    *  @PARAMS:
    *  	 Null
    *  @OUTPUT:
    *    Returns: byte[] IV
    *    Creates: IV¡£hex file.
    */
   
	private static byte[] createIV() throws IOException
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
		byte[] bIV = new byte[16];
		random.nextBytes(bIV);
		 ToHEX(bIV,"IV.hex");
		
		return bIV;
	}
	
   /*
    *  public static void ToHEX(byte[], String)
    *  @PARAMS:
    *  String String fileNam: name of the file
    *  @OUTPUT:
    *    Returns: IV in byte[]
    *    Creates: nothing.
    */
   
   private static byte[] IVFromHex(String filename) throws IOException {
	    BufferedReader reader = new BufferedReader( new FileReader (filename));
	    String line  = null;
	    StringBuilder stringBuilder = new StringBuilder();
//		    String ls = System.getProperty("line.separator");
	    while( ( line = reader.readLine() ) != null ) {
	        stringBuilder.append( line );
//		        stringBuilder.append( ls );
	    }
	    String sIV = stringBuilder.toString();
	    int len = sIV.length();
	    byte[] bIV = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        bIV[i / 2] = (byte) ((Character.digit(sIV.charAt(i), 16) << 4)
	                             + Character.digit(sIV.charAt(i+1), 16));
	    }
	    return bIV;
	}
   
   public void encrypt(){
	   try{
		   InputStream fin = new FileInputStream(clearText); 
		   OutputStream fout = new FileOutputStream(cipherText);
		   fout = new CipherOutputStream(fout,ecipher);
		   int numRead = 0;
		   while((numRead = fin.read(buffer)) >= 0){
			   fout.write(buffer,0,numRead);
		   }
		   fout.close();
	   }catch(IOException e){
	   }
   }
   
   public void decrypt(){
	   try{
		   InputStream fin = new FileInputStream(cipherText);
		   OutputStream fout = new FileOutputStream("plaintextD-AES256.txt");
		   fin = new CipherInputStream(fin,dcipher);
		   int numRead = 0;
		   while((numRead = fin.read(buffer)) >= 0){
			   fout.write(buffer,0,numRead);
		   }
		   fout.close();
	   }catch(IOException e){
	   }
   }
   
   public static void main(String[] args) throws Exception{ 
	   //Key used for AES256 encryption	
	   String InitialKey = "2011BCSChampion-AuburnUniversity";
	   //Export to "AES256Key.hex"
	   ToHEX(InitialKey.getBytes(),"AES256Key.hex");
	   
	   AES256DecryptFile AES256 = new AES256DecryptFile(InitialKey,"plaintext.txt","ciphertext-AES-256.txt");
	   AES256.decrypt();
   }
 
 }