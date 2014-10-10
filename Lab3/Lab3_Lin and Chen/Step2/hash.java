import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

import biz.source_code.base64Coder.Base64Coder;

/*
 * lab 3 step 2
 * Guo & Hou
 */

public class hash {

	public static void main(String[] args) {

		try {

			MessageDigest hash = MessageDigest.getInstance("SHA-256");
			hash.update(getBytesFromFile(new File("plaintext.txt")));
			byte[] digest = hash.digest();

			FileOutputStream fos = new FileOutputStream("Hash.txt");
			// convert the digest into a string
			String encodedString = Base64Coder.encodeLines(digest, 0, digest.length, 76, "");

			fos.write(encodedString.getBytes());
			fos.close();

		} catch (IOException e) {
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
		byte[] bytes = new byte[(int) length];

		// Read in the bytes
		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
			offset += numRead;
		}

		// Ensure all the bytes have been read in
		if (offset < bytes.length) {
			throw new IOException("Could not completely read file " + file.getName());
		}

		// Close the input stream and return bytes
		is.close();
		return bytes;
	}

}
