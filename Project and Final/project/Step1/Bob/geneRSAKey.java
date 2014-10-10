
import java.io.FileNotFoundException;
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
public class geneRSAKey {
	private PrivateKey privateKey;
	private PublicKey  publicKey;
	public geneRSAKey(){

		try {

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			KeyPair keypair = keyGen.genKeyPair();
			privateKey = keypair.getPrivate();
			publicKey = keypair.getPublic();
		} catch (java.security.NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm");
		}

	}
	public PrivateKey getPrivateKey(){
		return privateKey;
	}
	public byte[] getPrivateKeyInByte(){
		return privateKey.getEncoded();
	}
	public PublicKey getPublicKey(){
		return publicKey;
	}
	public byte[] getPublicKeyInByte(){
		return publicKey.getEncoded();
	}
	public void savePrivateKey() throws IOException{
		byte[] priv = privateKey.getEncoded();
		String Base64Key = Base64Coder.encodeLines(priv);
		FileOutputStream fos1 = new FileOutputStream("SB.txt");
		fos1.write(bytesToHexString(Base64Key.getBytes()).getBytes());
		fos1.close();
	}
	public void savePublicKey() throws IOException{
		byte[] pub = publicKey.getEncoded();
		String Base64Key = Base64Coder.encodeLines(pub);
		FileOutputStream fos1 = new FileOutputStream("PB.txt");
		fos1.write(bytesToHexString(Base64Key.getBytes()).getBytes());
		fos1.close();
	}	
	 private  String bytesToHexString(byte[] src){
	        StringBuilder stringBuilder = new StringBuilder("");
	        if (src == null || src.length <= 0) {
	            return null;
	        }
	        for (int i = 0; i < src.length; i++) {
	            int v = src[i] & 0xFF;
	            String hv = Integer.toHexString(v);
	            if (hv.length() < 2) {
	                stringBuilder.append(0);
	            }
	            stringBuilder.append(hv);
	        }
	        return stringBuilder.toString();
	    }
}