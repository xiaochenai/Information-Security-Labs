import java.io.*;
import biz.source_code.base64Coder.Base64Coder;
import java.security.*;
import java.security.spec.*;
import java.security.KeyFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * lab 3 step 3 Guo & Hou
 */

public class sign {

	public static String getStringFromFile(String filename) throws IOException {

		BufferedReader reader = new BufferedReader(new FileReader(filename));
		StringBuilder stringBuilder = new StringBuilder();
		String line = null;

		while ((line = reader.readLine()) != null) {
			stringBuilder.append(line);
		}

		return stringBuilder.toString();
	}

	public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {

		try {
			String privateKeyString = getStringFromFile("Kprivate.txt");
			byte[] privateKeyBytes = Base64Coder.decode(privateKeyString);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);
			//read the AES-256 hash from file
			String shash = getStringFromFile("hash.txt");
			byte[] bhash = Base64Coder.decode(shash);
			
			/*Cipher  cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey2);
			byte[] cipherData = cipher.doFinal(bhash);*/
			
			
			

			Signature dsa = Signature.getInstance("SHA256withRSA");
			dsa.initSign(privateKey2);



			dsa.update(bhash);
			byte[] realSig = dsa.sign();

			String encodedString = Base64Coder.encodeLines(realSig, 0, realSig.length, 76, "");
			FileOutputStream output = new FileOutputStream("Sig.txt");
			output.write(encodedString.getBytes());
			output.close();

		} catch (IOException e) {
		}

		catch (java.security.spec.InvalidKeySpecException e) {
			System.out.println("Invalid Key Spec Exception");
		} /*catch (java.security.SignatureException e) {
			System.out.println("Signature Exception");
		} */catch (java.security.InvalidKeyException e) {
			System.out.println("Invalid Key");
		} catch (java.security.NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm");
		}

	}

}
