import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import biz.source_code.base64Coder.Base64Coder;

/** 
 * lab 3 step 6
 * Guo & Hou
 */
 

public class wrap {

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

		try{
			String publicKeyString = getStringFromFile("Kpublic.txt");
			byte[] publicKeyByte = Base64Coder.decode(publicKeyString);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyByte);
			PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);

			String randString = getStringFromFile("RAND.txt");
			byte[] rand = Base64Coder.decode(randString);

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			System.out.println("rand length :" + rand.length);
			byte[] cipherData = cipher.doFinal(rand);

			String encodedString = Base64Coder.encodeLines(cipherData, 0, cipherData.length, 76, "");
			FileOutputStream output = new FileOutputStream("En-Ran.txt");
			output.write(encodedString.getBytes());
			output.close();


		} catch(java.security.spec.InvalidKeySpecException e){
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
