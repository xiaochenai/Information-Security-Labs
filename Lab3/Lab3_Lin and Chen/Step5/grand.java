import java.io.FileOutputStream;
import java.security.SecureRandom;

import biz.source_code.base64Coder.Base64Coder;


/*
 * lab 3 step 5 
 * Guo & Hou
 */

public class grand {

	public static void main(String[] argv) throws Exception {
		// Create a secure random number generator
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(System.nanoTime());
		// Get 1024 random bits
		byte[] bytes = new byte[1024/8];
		sr.nextBytes(bytes);

		// save the random number in base64 format
		String encodedString = Base64Coder.encodeLines(bytes, 0, bytes.length, 76, "");
		FileOutputStream output = new FileOutputStream("RAND.txt");
		output.write(encodedString.getBytes());
		output.close();

	}
}