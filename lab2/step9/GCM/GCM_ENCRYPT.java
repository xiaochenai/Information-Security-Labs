/*References: 
  http://developer-content.emc.com/docs/rsashare/share_for_java/1.1/dev_guide
                /group__JCESAMPLES__ENCDEC__SYMCIPHER__AESGCM.html
*/
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;




public class GCM_ENCRYPT

{
	
  public static void main(String[] arg) throws IOException
  {
      
	  
   
        try
        {
        	
          String InitialKey = "2011BCSChampion-AuburnUniversity";
          ToHEX(InitialKey.getBytes(),"GCMKey.hex");
          System.out.println("Key Saved into GCMKey.hex");
          KeyGenerator keyGen = KeyGenerator.getInstance("AES");
          keyGen.init(256,new SecureRandom(InitialKey.getBytes()));
          SecretKey key = keyGen.generateKey();
          Encrypter encrypter = new Encrypter(key);
          // Encrypt
          encrypter.encrypt(getBytesFromFile(new File("plaintext.txt")),"ciphertext-GCM.txt");
        
          FileOutputStream output = new FileOutputStream("key.dat");  
          output.write(key.getEncoded());
          output.close();
          for (byte b : key.getEncoded()) {
              System.out.format("%02x", b);
              }
          System.out.println("\nKey written to key.dat");
        }
        catch(Exception e)
        {
          System.out.println(e.getMessage());
          
        }
       }
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
        int numRead = 0;
        while (offset < bytes.length
               && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
            offset += numRead;
        }
    
        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "+file.getName());
        }
    
        // Close the input stream and return bytes
        is.close();
        return bytes;
    }
    
}
    
class Encrypter {
    Cipher ecipher;
   
    Encrypter(SecretKey key) throws IOException {
    	 byte[] finaliv = new byte[21];
    	 byte[] newiv = createIV(); 
         // 21 bytes in total
         byte[] iv = new byte[]{ 
             // This is the authentication tag length (12).
            (byte) 0x0c,

            // This is the length of the authenticated data (10).
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0a,

            // This is the GCM IV data used for encryption and decryption.
            // These 12-bytes MUST be unique for a key choice
            // for security reasons
            };
            System.arraycopy(iv,0,finaliv,0,iv.length);
            System.arraycopy(newiv, 0, finaliv, 9, newiv.length);
            ToHEX(finaliv,"IV.hex");
            
            
      
      
      try {  
        ecipher = Cipher.getInstance("AES/GCM/NoPadding","JsafeJCE");
        
     
        IvParameterSpec params = new IvParameterSpec(finaliv);
        ecipher.init(Cipher.ENCRYPT_MODE, key, params);
        

        } catch (javax.crypto.NoSuchPaddingException e) { System.out.println(e.getMessage());
        } catch (java.security.NoSuchAlgorithmException e) { System.out.println(e.getMessage());
        } catch (java.security.InvalidKeyException e) { System.out.println(e.getMessage());
        } catch (IllegalArgumentException e) { System.out.println(e.getMessage());
        } catch (Exception e){
            System.out.println(e.getMessage());
        }
    }



	// Buffer used to transport the bytes from one stream to another
    byte[] buf = new byte[1024];


    public void encrypt(byte[] in, String out) {
        try {
                        
            byte[] encryptedMessage =new byte[ecipher.getOutputSize(in.length)];
             
            byte[] authenticatedData = new byte[10];
            int outputLenUpdate = ecipher.update(authenticatedData,0, authenticatedData.length, encryptedMessage, 0);
            
            outputLenUpdate += ecipher.update(in, 0, in.length, encryptedMessage, outputLenUpdate);           
            ecipher.doFinal(encryptedMessage,outputLenUpdate);
            System.out.println("Encryption Successful. Data Written to: " + out);
          
            FileOutputStream output = new FileOutputStream(out);  
            output.write(encryptedMessage);
            output.close();
            
        
        } catch (Exception e){System.out.println("Decryption Failed: " + e.getMessage());
        }
    }
    
	public static byte[] createIV() throws IOException
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
		byte[] bIV = new byte[12];
		random.nextBytes(bIV);
		
		
		return bIV;
	}
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
 
}
