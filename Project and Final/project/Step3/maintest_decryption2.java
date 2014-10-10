import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import biz.source_code.base64Coder.Base64Coder;


public class maintest_decryption2 {
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException{
		
		System.out.println("enter you password");
		String PSW = easyscanner.nextString();
		//first to decrypt salt
		
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG","JsafeJCE");
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		MessageDigest hash = MessageDigest.getInstance("SHA-256");
		hash.update(PSW.getBytes());
		for(int i = 0; i<1000;i++){
			hash.update(hash.digest());
		}
		byte[] digest2 = hash.digest();
		System.out.println("digest2 : " + Base64Coder.encodeLines(digest2));
		secureRandom.setSeed(digest2);
		generator.init(secureRandom);
		SecretKey key2_1 = generator.generateKey();
		byte[] IV2_1 = new byte[16];
		System.arraycopy(digest2, 0, IV2_1, 0, 16);
		System.out.println("IV2_1 : " + Base64Coder.encodeLines(IV2_1));
		System.out.println("key2 : " + Base64Coder.encodeLines(key2_1.getEncoded()));
		//unwrap salt		
		unWrap unwrap = new unWrap(getBytesFromFile(new File("wrappedsalt.txt")),key2_1,IV2_1);
		byte[] unwrapsalt = unwrap.doUnWrap();
		System.out.println("salt : " + Base64Coder.encodeLines(unwrapsalt));
		//use salt to derive MK
		keyDeriveFunction KDF = new keyDeriveFunction(PSW.getBytes(),unwrapsalt,3,1032);
		KDF.DeriveMK();
		byte[] MK = KDF.GetMK();
		System.out.println("MK in Base64   :   "  + Base64Coder.encodeLines(MK));
		hash = MessageDigest.getInstance("SHA-512");
		hash.update(unwrapsalt);
		byte[] salt_2 = hash.digest();
		//gene DPK's KWK
		KDF = new keyDeriveFunction(MK,salt_2,10000,1024);
		KDF.DeriveMK();
		byte[] DPK_KWK = KDF.GetMK();
		GeneAESKeyandIV GeneAESIV = new GeneAESKeyandIV(DPK_KWK);
		System.out.println("DPK_KWK in Base64   :   "  + Base64Coder.encodeLines(DPK_KWK));
		
		SecretKey key_KWK = GeneAESIV.getKey();
		byte[] IV_KWK = GeneAESIV.getIV();


		//get DPK
		byte[] a =getBytesFromFile(new File("DPK.txt"));
		DecryptFile decryptFile = new DecryptFile(key_KWK,IV_KWK,a);
		byte[] DPKandIV  = decryptFile.decryption();
		byte[] IV_DPK = new byte[12];
		System.arraycopy(DPKandIV, 0, IV_DPK, 0, 12);
		byte[] DPKinBytes = new byte[DPKandIV.length-12];
		System.arraycopy(DPKandIV, 12, DPKinBytes, 0, DPKinBytes.length);
		SecretKey key_DPK = new SecretKeySpec(DPKinBytes,"AES");
		//decrypt file using DPK
		decryptFile = new DecryptFile(key_DPK,IV_DPK,getBytesFromFile(new File("ciphertext.txt")));
		decryptFile.decryption();
		decryptFile.SavePlaintexttoFile();
		
		
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

}
