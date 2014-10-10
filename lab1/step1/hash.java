import java.math.*;

import java.io.*;


import java.security.*;


 
 
public class hash {

    public static void main(String[] args) 
    {
       
	    try {
			FileInputStream in = new FileInputStream("plaintext.txt");
			StringBuffer buf = new StringBuffer();

			int ch=0;
			while((ch = in.read())> -1)
			{
				
				buf.append((char)ch);				
			}
			
			

			
			MessageDigest hash = MessageDigest.getInstance("SHA-256");
			hash.update(getBytesFromFile(new File("plaintext.txt")));
			byte[] digest = hash.digest();
			System.out.println("The hash bytes[]of plaintext.txt is ");
			for(int i = 0; i < digest.length; i++)
			{
				System.out.print(digest[i]);
			}
			System.out.println();
			System.out.println();
			BigInteger bi = new BigInteger(digest);
			
			String s = bi.toString(2);
			//System.out.println(s);
			System.out.println("The hash in binary is");
			System.out.println(s);
			System.out.println();
			System.out.println();
			//System.out.println(digest);
			
			FileOutputStream fos = new FileOutputStream("SHA256Hash.bin");
			fos.write(s.getBytes());
			fos.close();
			fos = new FileOutputStream("SHA256Hash.txt");
			
			
    		// If desired, convert the digest into a string
    		sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
			String encodedString = encoder.encodeBuffer(digest);
			System.out.println("The hash of plaintext.txt in BASE64 is");
			System.out.println(encodedString);
			fos.write(encodedString.getBytes());
			fos.close();
			
			
			
			/*
			sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
			String encodedString = encoder.encodeBuffer(digest);
			
			System.out.println(encodedString);
			
			sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
			byte [] decodedString = decoder.decodeBuffer(encodedString);
			
			System.out.println(decodedString);
			*/
			
    	} catch (IOException e){
		} catch (java.security.NoSuchAlgorithmException e) {
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
