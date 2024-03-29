	/*
 * DESedeEncryptFile.java
 * Lincoln Anderson
 * ELEC 5150
 * Spring 08
 * Lab 2 Part 1
 *
 */
 
 import java.io.*;
import java.math.BigInteger;
 import java.util.*;
 import java.security.*;
 import java.security.spec.*;
 import javax.crypto.*;
import javax.crypto.spec.*;
 
 public class DESedeEncryptFile{
 
   private SecretKey key;                 		  /* key used by encrypt/decrypt routines */
   private String cipherAlgorithm = "DESede";        /* Algorithm used for encrypt/decrypt, for example DESede or AES(Rijndael) */
   private String clearText;              		  /* name of file to store clear text output.  encrypt routine takes this as input stream */
   private String cipherText;             		  /* name of file to store cipher text output.  decrypt routine takes this as input stream */
   private Cipher ecipher;
   private Cipher dcipher;
   byte[] buffer = new byte[1024];
   
   /*
    *  public DESedeEncryptFile(String,String,String)
    *  @PARAMS:
    *  String initKey: key material used to create the Key
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: EncryptFile object
    */
   
   public DESedeEncryptFile(String initKey, String clearText, String cipherText) throws Exception{
	 //translate the key  
     this.key = toKey(initKey.getBytes());
     this.clearText = clearText;
     this.cipherText = cipherText;
     // Create an 8-byte initialization vector
     byte[] iv = createIV();
     AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
     try {
    	 ecipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    	 dcipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
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
    *  public DESedeEncryptFile(SecretKey,String,String)
    *  @PARAMS:
    *  SecretKey key: key object to store in class variable key
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: EncryptFile object
    */
   
   public DESedeEncryptFile(SecretKey key, String clearText, String cipherText){
     this.key = key;
     this.clearText = clearText;
     this.cipherText = cipherText;
     // Create an 8-byte initialization vector
     byte[] iv = new byte[]{
    		 (byte)0x8E, 0x12, 0x39, (byte)0x9C,
    		 0x07, 0x72, 0x6F, 0x5A
     };
     AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
     try {
    	 ecipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    	 dcipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
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
    *  public DESedeEncryptFile(String,String)
    *  @PARAMS:
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: EncryptFile object with DESede as default algorithm, creating a DESede key
    */
 
   public DESedeEncryptFile(String clearText, String cipherText){
     key = efKeyGenerator(cipherAlgorithm);
     this.clearText = clearText;
     this.cipherText = cipherText;
     // Create an 8-byte initialization vector
     byte[] iv = new byte[]{
    		 (byte)0x8E, 0x12, 0x39, (byte)0x9C,
    		 0x07, 0x72, 0x6F, 0x5A
     };
     AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
     try {
    	 ecipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    	 dcipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
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
    *  private SecretKey toKey(byte[])
    *  @PARAMS:
    *  byte[] key: translate initial key to secret key
    *  @OUTPUT:
    *    Returns: SecretKey key
    *    Creates: nothing.
    */
   
   private static SecretKey toKey(byte[] key) throws Exception {   
        DESedeKeySpec dks = new DESedeKeySpec(key);   
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");   
        SecretKey secretKey = keyFactory.generateSecret(dks);    
        return secretKey;   
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
	   System.out.println(text.length);
		for(int i = 0; i < text.length; i++)
		{	System.out.println(i+"text"+text[i]);
			String hex = Integer.toHexString(text[i]&0xFF );
			System.out.println("text[]&0xff"+(text[i]&0xFF));
			System.out.println(hex);
			if (hex.length() == 1) {
			    hex = "0" + hex;
			    System.out.println("ss"+hex);
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
    *    Creates: IV��hex file.
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
		byte[] bIV = new byte[8];
		random.nextBytes(bIV);
		System.out.println("bIV"+bIV[0]);
		 ToHEX(bIV,"IV.hex");
		
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
   

   
   
   public static void main(String[] args) throws IOException{
	   //Key used for DESede encryption	
	   String InitialKey = "2011BCSChampionAuburnUni";
	   //Export to "DESedeKey.hex"
	   ToHEX(InitialKey.getBytes(),"3DESKey.hex");
	   
	   try{
		   DESedeEncryptFile DESede = new DESedeEncryptFile(InitialKey,"plaintext.txt","ciphertext3DES.txt");
		   DESede.encrypt();
	   }catch(Exception e){
	   }
   }
 
 }