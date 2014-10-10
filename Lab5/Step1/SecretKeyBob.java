import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.security.Security; 

import biz.source_code.base64Coder.Base64Coder;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.util.Date;
import java.text.SimpleDateFormat;
import javax.crypto.spec.*;





public class SecretKeyBob {

	public static void main(String[] args) throws Exception{
		
//		FileInputStream input = new FileInputStream("Param.txt");
//		int length = input.available();
//		byte[] buffer = new byte[length];
//		input.read(buffer);
//		String Param = new String(buffer);
//		String[] values = Param.split(",");
//		BigInteger p = new BigInteger(values[0]);
//		BigInteger g = new BigInteger(values[1]);
//		int l = Integer.parseInt(values[2]);
//		DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
//		SecureRandom random = SecureRandom.getInstance("ECDRBG", "JsafeJCE");
		KeyPairGenerator ecKeyPairGenerator = KeyPairGenerator.getInstance("ECDH", "JsafeJCE");
		//from here we can know that if we use the same std name we can get the same ECGenParaterSpec
		// so it does not matter whether we can transfer the Param to other party
		ECGenParameterSpec ecParamSpec_1 = new ECGenParameterSpec("P256");
		ECGenParameterSpec ecParamSpec_2 = new ECGenParameterSpec("P256");
		
		
		EcdhKeyAgreementParty party_Bob = new EcdhKeyAgreementParty("Bob",ecParamSpec_1);
		EcdhKeyAgreementParty party_Alice = new EcdhKeyAgreementParty("Alice",ecParamSpec_2);
		
		String pubkey_Bob 	= Base64Coder.encodeLines(party_Bob.getPublicKeyBytes());
		String pubkey_Alice = Base64Coder.encodeLines(party_Alice.getPublicKeyBytes());
		String priv_Bob		= Base64Coder.encodeLines(party_Bob.getPrivateKeyBytes());
		String priv_Alice	= Base64Coder.encodeLines(party_Alice.getPrivateKeyBytes());
		
		
		
		party_Bob.doFinalPhase(party_Alice.getPublicKeyBytes());
		party_Alice.doFinalPhase(party_Bob.getPublicKeyBytes());
		
		
		String secreteKey_Bob 	= Base64Coder.encodeLines(party_Bob.showSharedSecret());
		String secreteKey_Alice = Base64Coder.encodeLines(party_Alice.showSharedSecret());
		System.out.println("Bob's Secrete Key in Base64 : " + secreteKey_Bob);
		System.out.println("Allice's Secrete Key in Base64 : " + secreteKey_Alice);
		MessageDigest hash_Bob = MessageDigest.getInstance("SHA-256");
		hash_Bob.update(party_Bob.showSharedSecret());
		MessageDigest hash_Alice = MessageDigest.getInstance("SHA-256");
		hash_Alice.update(party_Alice.showSharedSecret());
		
		for(int i = 0; i<1000;i++){
			hash_Bob.update(hash_Bob.digest());
			hash_Alice.update(hash_Alice.digest());
		}
		
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom1.setSeed(hash_Bob.digest());
		generator.init(256, secureRandom1);
		
		SecretKey Bob_AES = generator.generateKey();
		
		SecureRandom secureRandom2 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom2.setSeed(hash_Alice.digest());
		generator.init(256,secureRandom2);
		SecretKey Alice_AES = generator.generateKey();
		
		byte[] IV_Bob = new byte[12];
		byte[] IV_Alice = new byte[12];
		
		byte[] IV1 = hash_Bob.digest();
		byte[] IV2 = hash_Alice.digest();
		
		System.arraycopy(IV1, 0, IV_Bob, 0, 12);
		System.arraycopy(IV2, 0, IV_Alice, 0, 12);
        int length_Bob = Bob_AES.getEncoded().length;
        int length_Alice = Alice_AES.getEncoded().length;
		byte[] IVandKey_Bob = new byte[12+length_Bob];
		byte[] IVandKey_Alice = new byte[12+length_Alice];
		
		System.arraycopy(IV_Bob, 0, IVandKey_Bob, 0, 12);
		System.arraycopy(Bob_AES.getEncoded(), 0, IVandKey_Bob, 12, length_Bob);
		System.arraycopy(IV_Alice, 0, IVandKey_Alice, 0, 12);
		System.arraycopy(Alice_AES.getEncoded(), 0, IVandKey_Alice, 12, length_Alice);
		
		//the first 12 byte is IV and the others are key
		FileOutputStream fos = new FileOutputStream("A-AES.txt");
		fos.write(Base64Coder.encodeLines(IVandKey_Bob).getBytes());
		fos.close();
		
		fos = new FileOutputStream("B-AES.txt");
		fos.write(Base64Coder.encodeLines(IVandKey_Alice).getBytes());
		fos.close();
		
		fos = new FileOutputStream("AP.txt");
		fos.write(pubkey_Alice.getBytes());
		fos.close();
		fos = new FileOutputStream("BP.txt");
		fos.write(pubkey_Bob.getBytes());
		fos.close();
		fos = new FileOutputStream("AS.txt");
		fos.write(priv_Alice.getBytes());
		fos.close();
		fos = new FileOutputStream("BS.txt");
		fos.write(priv_Bob.getBytes());
		fos.close();
		
		
		
			
			
		
		
	}
}
