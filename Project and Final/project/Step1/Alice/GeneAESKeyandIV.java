

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import biz.source_code.base64Coder.Base64Coder;
public class GeneAESKeyandIV {
	private SecretKey key;
	private byte[] IV;
	public GeneAESKeyandIV() throws IOException, NoSuchAlgorithmException, NoSuchProviderException{
		SecureRandom secureRandom = SecureRandom.getInstance("ECDRBG","JsafeJCE");
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		secureRandom.setSeed(GeneTimeSeed());
		generator.init(256,secureRandom);
		//get AES256 Key
		key = generator.generateKey();
		IV = createIV();
		
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
	private byte[] createIV() throws NoSuchAlgorithmException, NoSuchProviderException, IOException{
		SecureRandom random = SecureRandom.getInstance("ECDRBG","JsafeJCE");
		random.setSeed(GeneTimeSeed());
		byte[] bIV = new byte[12];
		random.nextBytes(bIV);
		return bIV;
	}
//	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException{
//		byte[] a = new GeneAESKeyandIV().GeneTimeSeed();
//		String A = Base64Coder.encodeLines(a);
//		System.out.println("A : " + A);
//		byte[] b = new GeneAESKeyandIV().GeneTimeSeed();
//		String B = Base64Coder.encodeLines(b);
//		System.out.println("B : " + B);
//		byte[] c = new GeneAESKeyandIV().GeneTimeSeed();
//		String C = Base64Coder.encodeLines(c);
//		System.out.println("C : " + C);
//	}
	public SecretKey getKey(){
		return key;
	}
	public byte[] getKeyinByte(){
		return key.getEncoded();
	}
	public byte[] getIV(){
		return IV;
	}
	public void saveKeytoFile() throws IOException{
		byte[] keyByte = key.getEncoded();
		String Base64Key = Base64Coder.encodeLines(keyByte, 0, keyByte.length, 76, "");
		FileOutputStream fos1 = new FileOutputStream("AES256.txt");
		fos1.write(Base64Key.getBytes());
		fos1.close();
	}
	public void saveIVtoFile() throws IOException{
		String Base64Key = Base64Coder.encodeLines(IV, 0, IV.length, 76, "");
		FileOutputStream fos1 = new FileOutputStream("IV.txt");
		fos1.write(Base64Key.getBytes());
		fos1.close();
	}
	public byte[] GetKeyandIV(){
		byte[] KeyandIV = new byte[IV.length+key.getEncoded().length];
		System.arraycopy(IV, 0, KeyandIV, 0, IV.length);
		System.arraycopy(key.getEncoded(), 0, KeyandIV, IV.length, key.getEncoded().length);
		return KeyandIV;
	}
	public void SaveKeyandIV() throws IOException{
		byte[] KeyandIV = new byte[IV.length+key.getEncoded().length];
		System.arraycopy(IV, 0, KeyandIV, 0, IV.length);
		System.arraycopy(key.getEncoded(), 0, KeyandIV, IV.length, key.getEncoded().length);
		FileOutputStream fos1 = new FileOutputStream("KeyandIV.txt");
		fos1.write(KeyandIV);
		fos1.close();
	}
}
