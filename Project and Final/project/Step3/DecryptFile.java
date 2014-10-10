

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import biz.source_code.base64Coder.Base64Coder;

import com.rsa.jsafe.provider.GCMParameterSpec;

public class DecryptFile {
	private SecretKey key;
	private byte[] IV;
	private byte[] plaintext;
	private byte[] ciphertext;
	public DecryptFile(SecretKey key,byte[] IV, byte[] ciphertext){
		this.key = key;
		this.IV  = IV;
		this.ciphertext = ciphertext;
	}
	public byte[] decryption(){
		GCMParameterSpec gcmParams = new GCMParameterSpec(IV);
		try{
			Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "JsafeJCE");
			aes.init(Cipher.DECRYPT_MODE, key, gcmParams);
			plaintext = aes.doFinal(ciphertext);
		}catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return plaintext;
		
	}
	public void SavePlaintexttoFile() throws IOException{

		FileOutputStream fos1 = new FileOutputStream("plaintext.txt");
		fos1.write(plaintext);
		fos1.close();
	}
	
	
}
