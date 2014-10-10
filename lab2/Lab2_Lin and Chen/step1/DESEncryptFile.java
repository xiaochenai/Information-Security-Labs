/*
 * DESEncryptFile.java
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
 
 public class DESEncryptFile{
 
   private SecretKey Skey;                 		  /* key used by encrypt/decrypt routines */
   private String cipherAlgorithm = "DES";        /* Algorithm used for encrypt/decrypt, for example DES or AES(Rijndael) */
   private String clearText;              		  /* name of file to store clear text output.  encrypt routine takes this as input stream */
   private String cipherText;             		  /* name of file to store cipher text output.  decrypt routine takes this as input stream */
   private Cipher ecipher;
   private Cipher dcipher;
   byte[] buffer = new byte[1024];
   /*
    *  public DESEncryptFile(String,String,String)
    *  @PARAMS:
    *  String initKey: key material used to create the Key
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: EncryptFile object
    */
   
   public DESEncryptFile(String initKey, String clearText, String cipherText) throws Exception{
	 //translate the key  
     this.Skey = toKey(initKey.getBytes());
     this.clearText = clearText;
     this.cipherText = cipherText;
     // Create an 8-byte initialization vector
     byte[] iv = createiv();
     AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
     try {
    	 ecipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    	 dcipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    	 // CBC requires an initialization vector
    	 ecipher.init(Cipher.ENCRYPT_MODE, Skey, paramSpec);
    	 dcipher.init(Cipher.DECRYPT_MODE, Skey, paramSpec);
     } catch (java.security.InvalidAlgorithmParameterException e) {
     } catch (javax.crypto.NoSuchPaddingException e) {
     } catch (java.security.NoSuchAlgorithmException e) {
     } catch (java.security.InvalidKeyException e) {
     }
   }
   /*
    *  public DESEncryptFile(SecretKey,String,String)
    *  @PARAMS:
    *  SecretKey key: key object to store in class variable key
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: EncryptFile object
    */
   
   public DESEncryptFile(SecretKey key, String clearText, String cipherText) throws IOException{
     this.Skey = key;
     this.clearText = clearText;
     this.cipherText = cipherText;
     // Create an 8-byte initialization vector
     byte[] iv = createiv();
     
     AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
     try {
    	 ecipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    	 dcipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    	 // CBC requires an initialization vector
    	 ecipher.init(Cipher.ENCRYPT_MODE, Skey, paramSpec);
    	 dcipher.init(Cipher.DECRYPT_MODE, Skey, paramSpec);
     } catch (java.security.InvalidAlgorithmParameterException e) {
     } catch (javax.crypto.NoSuchPaddingException e) {
     } catch (java.security.NoSuchAlgorithmException e) {
     } catch (java.security.InvalidKeyException e) {
     }
   }
   
   /*
    *  public DESEncryptFile(String,String)
    *  @PARAMS:
    *  String clearText: name of file to store clear text output.
    *  String cipherText: name of file to store cipher text output.
    *  @OUTPUT:
    *    Returns: nothing.
    *    Creates: EncryptFile object with DES as default algorithm, creating a DES key
    */

   public DESEncryptFile(String clearText, String cipherText){
     Skey = efKeyGenerator(cipherAlgorithm);
     this.clearText = clearText;
     this.cipherText = cipherText;
     // Create an 8-byte initialization vector
     byte[] iv = new byte[]{
    		 (byte)0x8E, 0x12, 0x39, (byte)0x9C,
    		 0x07, 0x72, 0x6F, 0x5A
     };
     AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
     try {
    	 ecipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    	 dcipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    	 // CBC requires an initialization vector
    	 ecipher.init(Cipher.ENCRYPT_MODE, Skey, paramSpec);
    	 dcipher.init(Cipher.DECRYPT_MODE, Skey, paramSpec);
     } catch (java.security.InvalidAlgorithmParameterException e) {
     } catch (javax.crypto.NoSuchPaddingException e) {
     } catch (java.security.NoSuchAlgorithmException e) {
     } catch (java.security.InvalidKeyException e) {
     }
   }   
   private byte[] createiv() throws IOException
   {
	   SecureRandom random = null;
	   try{
		   random = SecureRandom.getInstance("SHA1PRNG");
	   }
	   catch(NoSuchAlgorithmException e){
		System.out.println("NoSuchAlgorithmException:" + e);
		System.exit(-1);
	   }
	   byte[] bIV = new byte[8];
	   random.nextBytes(bIV);
	   ToHEX(bIV,"IV.hex");
	   return bIV;
	   
   }
   public static void ToHEX(byte[] text ,String fileName ) throws IOException
   {
	   String hexString = "";
	   for(int i=0;i<text.length;i++)
	   {
		   String hex = Integer.toHexString(text[i]&0xFF);
		   if(hex.length() == 1)
		   {
			   hex = "0"+hex;
		   }
		   hexString = hexString + hex;
	   }
	   FileOutputStream fos = new FileOutputStream(fileName);
	   fos.write(hexString.getBytes());
	   fos.close();
   }
   private static SecretKey toKey(byte[] key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
	   DESKeySpec dks = new DESKeySpec(key);
	   SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");   
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
	public static byte[] getBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);
    
        // Get the size of the file
        long length = file.length();
    
        if (length > Integer.MAX_VALUE) {
            // File is too large
        }
    
        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];
    
        // Read in the bytes
        int offset = 0;
        int numRead = is.read(bytes, offset, bytes.length-offset);
        offset = offset + numRead;
    
        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "+file.getName());
        }
    
        // Close the input stream and return bytes
        is.close();
        return bytes;
    }
   
   public static void main(String[] args) throws IOException{
	   String InitialKey = "2011BCSC";
	   ToHEX(InitialKey.getBytes(),"DESKey.hex");
	   try{
		   DESEncryptFile des = new DESEncryptFile(InitialKey,"plaintext.txt","ciphertextDES.txt");
		   des.encrypt();
  		   /*
		   byte[] keydata = getBytesFromFile(new File("DESKey.hex"));
		   SecretKey secretekey = new SecretKeySpec(keydata,"DES");
		   byte[] keyd = secretekey.getEncoded();
		   String k = new String(keyd);
		   System.out.println("***:" +k );
		   System.out.println("format: " + secretekey.getFormat());
		   System.out.println(keydata.length);
		   KeyGenerator keyGen = KeyGenerator.getInstance("DES");
		   SecretKey key = keyGen.generateKey();
		   byte[] s = key.getEncoded();
		   String sk = new String(s);
		   System.out.println("length:" + s.length);
		   System.out.println("format:"+key.getFormat());
		   System.out.println("%%%%:"+sk);
		   //DESEncryptFile des = new DESEncryptFile("plaintext.txt","ciphertext.txt");
		   DESEncryptFile des = new DESEncryptFile(secretekey,"plaintext.txt","ciphertextDES.txt");
		   des.encrypt();*/
		   
	   }catch(Exception e){
	   }
   }
 
 }