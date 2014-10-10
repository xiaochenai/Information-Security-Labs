import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

import biz.source_code.base64Coder.Base64Coder;

/**
 * lab 3 step 7 
 * Guo & Hou
 */

public class unwrap {

	public static String getStringFromFile(String filename) throws IOException {

		BufferedReader reader = new BufferedReader(new FileReader(filename));
		StringBuilder stringBuilder = new StringBuilder();
		String line = null;

		while ((line = reader.readLine()) != null) {
			stringBuilder.append(line);
		}

		return stringBuilder.toString();
	}

	public static void main(String[] args) {

		try {

			String privateKeyString = getStringFromFile("Kprivate.txt");
			byte[] privateKeyBytes = Base64Coder.decode(privateKeyString);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

			String eRandString = getStringFromFile("En-RAN.txt");
			byte[] eRand = Base64Coder.decode(eRandString);

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey2);
			byte[] cipherData = cipher.doFinal(eRand);

			FileOutputStream output = new FileOutputStream("DE-Ran.txt");
			String decodedString = Base64Coder.encodeLines(cipherData, 0, cipherData.length, 76, "");
			output.write(decodedString.getBytes());
			output.close();

		} catch (java.security.spec.InvalidKeySpecException e) {
			System.out.println("Invalid Key Spec");
		} catch (java.security.InvalidKeyException e) {
			System.out.println("Invalid Key");
		} catch (java.security.NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm");
		} catch (javax.crypto.NoSuchPaddingException e) {
			System.out.println("No Such Padding");
		} catch (javax.crypto.IllegalBlockSizeException e) {
			System.out.println("Illegal Block Size");
		} catch (javax.crypto.BadPaddingException e) {
			System.out.println("Bad Padding");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
