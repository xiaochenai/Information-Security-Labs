/*References: 
  http://developer-content.emc.com/docs/rsashare/share_for_java/1.1/dev_guide
                /group__JCESAMPLES__ENCDEC__SYMCIPHER__AESGCM.html
*/

import java.io.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.security.SecureRandom;

public class GCM_DECRYPT
{
  public static void main(String[] arg) throws IOException
  {
      
        try
        {
          byte[] keyin = getBytesFromFile(new File("key.dat"));
          SecretKey  key = new SecretKeySpec(keyin, "AES");
          Decrypter decrypter = new Decrypter(key);
            // Encrypt
          decrypter.decrypt(getBytesFromFile(new File("ciphertext-GCM.txt")),"decipher-GCM.txt");
          
          
          
       
          System.out.println("Using Key: ");
          for (byte b : key.getEncoded()) {
              System.out.format("%02x", b);
              }
          
        }
        catch(Exception e)
        {
          System.out.println("Error in creating key");
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
    
class Decrypter {
    //Cipher ecipher;
    Cipher dcipher;

    Decrypter(SecretKey key) {
       
      try {
    	
    	  byte[] iv = new byte[]{ 
    	             // This is the authentication tag length (12).
    	            (byte) 0x0c,

    	            // This is the length of the authenticated data (10).
    	            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    	            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0a,
    	            };
         /* byte[] iv = new byte[]{ 
                  // This is the authentication tag length (12).
                 (byte) 0x0c,

                 // This is the length of the authenticated data (10).
                 (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                 (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0a,

                 // This is the GCM IV data used for encryption and decryption.
                 // These 12-bytes MUST be unique for a key choice
                 // for security reasons.
                 (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                 (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                 (byte) 0x18, (byte) 0x19, (byte) 0x20, (byte) 0x21,
                 };*/
    	byte[] finaliv = new byte[21];
    	byte[] newiv = IVFromHex("IV.hex");
    	System.arraycopy(iv,0,finaliv,0,iv.length);
        System.arraycopy(newiv, 0, finaliv, 9, newiv.length);
    	for(int i=0;i<newiv.length;i++)
    	{
    		
    		System.out.println(newiv[i]);
    	}
    	System.out.println("SSSSSS");
    	for(int i=0;i<finaliv.length;i++)
    	{
    		
    		System.out.println(finaliv[i]);
    	}
        dcipher = Cipher.getInstance("AES/GCM/NoPadding","JsafeJCE");
     
        IvParameterSpec params = new IvParameterSpec(finaliv);

        dcipher.init(Cipher.DECRYPT_MODE, key, params);
   
            //dcipher.init(Cipher.DECRYPT_MODE, key);
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

    private static byte[] IVFromHex(String filename) throws IOException {
	    BufferedReader reader = new BufferedReader( new FileReader (filename));
	    String line  = null;
	    StringBuilder stringBuilder = new StringBuilder();
	    while( ( line = reader.readLine() ) != null ) {
	        stringBuilder.append( line );
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
    public void decrypt(byte[] in, String out) {
        try {
           
          
            byte[] plainMessage = new byte[dcipher.getOutputSize(in.length)];
            byte[] authenticatedData = new byte[10];
            int outputLenUpdate = dcipher.update(authenticatedData,0, authenticatedData.length, plainMessage, 0);
            
            
            outputLenUpdate += dcipher.update(in, 0, in.length, plainMessage, outputLenUpdate);
           
            dcipher.doFinal(plainMessage,outputLenUpdate);
            
            FileOutputStream output = new FileOutputStream(out);  
            output.write(plainMessage);
            System.out.println("Decryption Successful. Written to: " + out);
            output.close();
            
        }  catch (Exception e){System.out.println("Decryption Failed: " + e.getMessage());
    }
    }
   
}
