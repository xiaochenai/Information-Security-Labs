package compare;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import javax.crypto.spec.DHParameterSpec;

import biz.source_code.base64Coder.Base64Coder;

/*
 * lab 3 step 1
 * Guo & Hou
 */
public class geneKeyPairDH {
	private PrivateKey privateKey;
	private PublicKey  publicKey;
	private DHParameterSpec agreedParameters;
	public geneKeyPairDH(DHParameterSpec dhSpec) throws NoSuchProviderException, IOException{

		try {
			this.agreedParameters = dhSpec;
			SecureRandom RAND = SecureRandom.getInstance("ECDRBG","JsafeJCE");
			RAND.setSeed(GeneTimeSeed());
			//ECGenParameterSpec agreedParameters = new ECGenParameterSpec("K571");
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
			keyGen.initialize(dhSpec,RAND);
			KeyPair keypair = keyGen.genKeyPair();
			privateKey = keypair.getPrivate();
			publicKey = keypair.getPublic();
		} catch (java.security.NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm");
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	private byte[] GeneTimeSeed() throws IOException{
		long starttime11  =System.currentTimeMillis();
		long nanoGMT2 = System.nanoTime();
		long a = new Date().getTime();
		ByteBuffer buffer = ByteBuffer.allocate(8);
		buffer.putLong(a);
		
		byte[] b = buffer.array();
		byte[] nanoBytes = ByteBuffer.allocate(8).putLong(nanoGMT2).array();
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(b);
		outputStream.write(nanoBytes);
		byte[] TimeSeed = outputStream.toByteArray();
		return TimeSeed;
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
		FileOutputStream fos1 = new FileOutputStream("SA.txt");
		fos1.write(bytesToHexString(Base64Key.getBytes()).getBytes());
		fos1.close();
	}
	public void savePublicKey() throws IOException{
		byte[] pub = publicKey.getEncoded();
		String Base64Key = Base64Coder.encodeLines(pub);
		FileOutputStream fos1 = new FileOutputStream("PA.txt");
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