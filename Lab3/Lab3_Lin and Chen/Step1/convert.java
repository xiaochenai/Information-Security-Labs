import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import biz.source_code.base64Coder.Base64Coder;

/*
 * lab 3 step 1
 * Guo & Hou
 */
public class convert {

	public static void main(String[] args) {

		try {

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			KeyPair keypair = keyGen.genKeyPair();
			PrivateKey privateKey = keypair.getPrivate();
			PublicKey publicKey = keypair.getPublic();

			byte[] priv = privateKey.getEncoded();
			/*
			 * FileOutputStream keyfos = new FileOutputStream("Kprivate");
			 * keyfos.write(priv); keyfos.close();
			 */
			byte[] pub = publicKey.getEncoded();
			/*
			 * keyfos = new FileOutputStream("Kpublic"); keyfos.write(pub);
			 * keyfos.close();
			 */
			String Base64Key = Base64Coder.encodeLines(priv, 0, priv.length, 76, "");
			FileOutputStream fos1 = new FileOutputStream("Kprivate.txt");
			fos1.write(Base64Key.getBytes());

			Base64Key = Base64Coder.encodeLines(pub, 0, pub.length, 76, "");
			fos1 = new FileOutputStream("Kpublic.txt");
			fos1.write(Base64Key.getBytes());

			fos1.close();
		} catch (IOException e) {
		} catch (java.security.NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm");
		}
		// catch(java.security.spec.InvalidKeySpecException
		// e){System.out.println("Invalid Key Spec Exception");}}
	}
}