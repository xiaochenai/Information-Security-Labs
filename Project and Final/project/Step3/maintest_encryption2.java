import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import biz.source_code.base64Coder.Base64Coder;


public class maintest_encryption2 {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IOException{
		geneSalt GeneSalt = new geneSalt();
		byte[] salt = GeneSalt.getSalt();
		System.out.println("enter you password");
		String Psw = easyscanner.nextString();
		keyDeriveFunction KDF = new keyDeriveFunction(Psw.getBytes(),salt,3,1032);
		KDF.DeriveMK();
		byte[] MK = KDF.GetMK();
		System.out.println("MK in Base64   :   "  + Base64Coder.encodeLines(MK));
		MessageDigest hash = MessageDigest.getInstance("SHA-512");
		hash.update(salt);
		byte[] salt_2 = hash.digest();
		//gene DPK's KWK
		KDF = new keyDeriveFunction(MK,salt_2,10000,1024);
		KDF.DeriveMK();
		byte[] DPK_KWK = KDF.GetMK();
		System.out.println("DPK_KWK in Base64  " + Base64Coder.encodeLines(DPK_KWK));
		GeneAESKeyandIV GeneAESIV = new GeneAESKeyandIV(DPK_KWK);
		
		SecretKey key_KWK = GeneAESIV.getKey();
		byte[] IV_KWK = GeneAESIV.getIV();
		GeneAESIV.SaveKeyandIV();
		//gene DPK
		GeneAESIV = new GeneAESKeyandIV(GeneTimeSeed());
		SecretKey key_DPK = GeneAESIV.getKey();
		byte[] IV_DPK = GeneAESIV.getIV();
		//encrypt file using DPK
		EncryptFile encryptFile = new EncryptFile(key_DPK,IV_DPK,getBytesFromFile(new File("plain.txt")));
		encryptFile.encryption();
		System.out.println("File encrypted.....");
		encryptFile.SaveCiphertoFile();
		System.out.println("cipher Saved.......");
		//encrypt DPK using KWK
		byte[] current = new byte[key_DPK.getEncoded().length + IV_DPK.length];
		System.arraycopy(IV_DPK, 0, current, 0, IV_DPK.length);
		System.arraycopy(key_DPK.getEncoded(), 0, current, IV_DPK.length, key_DPK.getEncoded().length);
		encryptFile = new EncryptFile(key_KWK,IV_KWK,current);
		encryptFile.encryption();
		encryptFile.SaveFileTo("DPK.txt");
		//gene KWK_2 to encrypt salt
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG","JsafeJCE");
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		hash = MessageDigest.getInstance("SHA-256");
		hash.update(Psw.getBytes());
		for(int i = 0; i<1000;i++){
			hash.update(hash.digest());
		}
		byte[] digest1 = hash.digest();
		System.out.println("digest 1 : " + Base64Coder.encodeLines(digest1));
		secureRandom.setSeed(digest1);
		generator.init(secureRandom);
		SecretKey key2 = generator.generateKey();
		byte[] IV2 = new byte[16];
		System.arraycopy(digest1, 0, IV2, 0, 16);
		System.out.println("IV2 : " + Base64Coder.encodeLines(IV2));
		System.out.println("key2 : " + Base64Coder.encodeLines(key2.getEncoded()));
		Wrap wrap = new Wrap(salt,key2,IV2);
		System.out.println("salt" + Base64Coder.encodeLines(salt));
		byte[] wrapSalt = wrap.doWrap();
		System.out.println("wrapSalt" + Base64Coder.encodeLines(wrapSalt));
		FileOutputStream fos1 = new FileOutputStream("wrappedsalt.txt");
		fos1.write(wrapSalt);
		fos1.close();
		
	
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
	private static byte[] GeneTimeSeed() throws IOException{
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
}