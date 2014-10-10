import java.math.*;

import java.io.*;

import biz.source_code.base64Coder.Base64Coder;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class hmac {
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
	public static void main(String[] args)
	{
		try{
			byte[] key = getBytesFromFile(new File("HMACKey"));
			SecretKey secretekey = new SecretKeySpec(key,"HmacSHA256");
			Mac mac = Mac.getInstance(secretekey.getAlgorithm());
			mac.init(secretekey);
			
			byte[] digest = mac.doFinal(getBytesFromFile(new File("plaintext.txt")));

			System.out.println();
			System.out.println();
			BigInteger big = new BigInteger(digest);
			

			System.out.println();
			String binary = big.toString(2);
			

			FileOutputStream fos = new FileOutputStream("HMAC256HASH.bin");
			fos.write(binary.getBytes());
			fos.close();
			String hex = big.toString(16);

			System.out.println();
			fos = new FileOutputStream("HMAC256HASH.hex");
			fos.write(hex.getBytes());
			fos.close();
		
			
			String encodeString = Base64Coder.encodeLines(digest);
			System.out.println("This is the HMACSHA256 digestString of plaintxt in BASE64 using the Key in HMACKey");
			System.out.println(encodeString);
			fos = new FileOutputStream("HMAC256HASH.txt");
			fos.write(encodeString.getBytes());
			fos.close();
			
			
			
		}catch(IOException e){}
		catch(java.security.NoSuchAlgorithmException e){}
		catch(java.security.InvalidKeyException e){}
	}
	
}
