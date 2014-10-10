
import java.io.*;

import javax.crypto.*;
//import sun.misc.BASE64Decoder;
import biz.source_code.base64Coder.Base64Coder;
import java.security.*;
import java.security.spec.*;
import java.security.KeyFactory;
import java.security.spec.EncodedKeySpec;


/**
 * lab 3 step 4 
 * Guo & Hou
 */

public class verify {

    private static final int MAX_ENCRYPT_BLOCK = 117;
    

    private static final int MAX_DECRYPT_BLOCK = 128;

	public static String getStringFromFile(String filename) throws IOException {

		BufferedReader reader = new BufferedReader(new FileReader(filename));
		StringBuilder stringBuilder = new StringBuilder();
		String line = null;

		while ((line = reader.readLine()) != null) {
			stringBuilder.append(line);
		}

		return stringBuilder.toString();
	}
	   
     
    public static byte[] decryptByPublicKey(byte[] encryptedData, byte[] publicKey)
            throws Exception {
        byte[] keyBytes = publicKey;
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

   
    public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey)
            throws Exception {
        byte[] keyBytes = publicKey;
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

	public static void main(String[] args) throws Exception {

		try {
			String publicKeyString = getStringFromFile("Kpublic.txt");
			byte[] publicKeyByte = Base64Coder.decode(publicKeyString);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyByte);
			PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);

			String sigToVerifyString = getStringFromFile("sig_En.txt");
			byte[] sigToVerify = Base64Coder.decode(sigToVerifyString);
			System.out.println("sigToVerifyString :" + sigToVerifyString);
			
			String shash = getStringFromFile("hash.txt");
			
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, pubKey);
			byte[] cipherData = cipher.doFinal(sigToVerify);
			String encodedString = Base64Coder.encodeLines(cipherData, 0, cipherData.length, 76, "");
			if(shash.equals(encodedString))
				System.out.println("Verify true");
			FileOutputStream output = new FileOutputStream("Sig_Dn.txt");
			output.write(encodedString.getBytes());
			output.close();
			
			/*****************************************/
			
			
			/*byte[] epByte = encryptByPublicKey(sigToVerify,publicKeyByte);
			String epStr =  Base64Coder.encodeLines(epByte);
			System.out.println("epStr :" + epStr);
			/*Cipher cipher =Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] epByte = cipher.doFinal(sigToVerify);
		    String epStr =  Base64Coder.encodeLines(epByte);
		    System.out.println("epStr :" + epStr);*/
		    /*if(epStr.equals(sigToVerifyString))
		    {
		    	System.out.println("*****true****");
		    }*/
			
			
		
			/*Signature sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(pubKey);
			
			String shash = getStringFromFile("hash.txt");
			byte[] bhash = Base64Coder.decode(shash);

			sig.update(bhash);

			boolean verifies = sig.verify(sigToVerify);
			System.out.println("signature verifies: " + verifies);*/
			

		} catch (java.security.spec.InvalidKeySpecException e) {
			System.out.println("Invalid Key Spec Exception");
		} /*catch (java.security.SignatureException e) {
			System.out.println("Signature Exception");
		}*/ catch (java.security.InvalidKeyException e) {
			System.out.println("Invalid Key");
		} catch (java.security.NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
