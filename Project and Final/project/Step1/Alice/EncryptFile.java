

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

public class EncryptFile {
	private SecretKey key;
	private byte[] IV;
	private byte[] plaintext;
	private byte[] ciphertext;
	public EncryptFile(SecretKey key,byte[] IV, byte[] plaintext){
		this.key = key;
		this.IV  = IV;
		this.plaintext = plaintext;
	}
	public byte[] encryption(){
		GCMParameterSpec gcmParams = new GCMParameterSpec(IV);
		try{
			Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "JsafeJCE");
			aes.init(Cipher.ENCRYPT_MODE, key, gcmParams);
			ciphertext = aes.doFinal(plaintext);
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
		return ciphertext;
		
	}
	public void SaveCiphertoFile() throws IOException{

		FileOutputStream fos1 = new FileOutputStream("ciphertext.txt");
		fos1.write(ciphertext);
		fos1.close();
	}
	public void SaveCiphertoFileinBase64() throws IOException{
		FileOutputStream fos1 = new FileOutputStream("ciphertextBASE64.txt");
		fos1.write(Base64Coder.encodeLines(ciphertext).getBytes());
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
