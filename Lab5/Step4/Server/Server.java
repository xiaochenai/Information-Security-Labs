import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import biz.source_code.base64Coder.Base64Coder;


public class Server {
	private static int port;
	public static void main(String[] args) throws Exception{
		System.out.println("enter the port number");
		port = easyscanner.nextInt();
		
		ServerSocket serverSocket = new ServerSocket(port);
	    Socket messageSocket = serverSocket.accept();
	    OutputStream out = messageSocket.getOutputStream();
	    InputStream in = messageSocket.getInputStream();
	    
	    System.out.println("waiting for public key from client.");
	    while (in.available() == 0) {}
	    System.out.println("Receive Public Key from Client");
	    byte[] receivedMsg = new byte[in.available()];
	    in.read(receivedMsg);
		
		ECGenParameterSpec ecParamSpec_1 = new ECGenParameterSpec("P256");
		EcdhKeyAgreementParty party_Alice = new EcdhKeyAgreementParty("Alice",ecParamSpec_1);
		System.out.println("This is Alice !");
		
		System.out.println("Generate Public key and Private key of Alcie");
		String pubkey_Alice 	= Base64Coder.encodeLines(party_Alice.getPublicKeyBytes());
		String priv_Alice		= Base64Coder.encodeLines(party_Alice.getPrivateKeyBytes());
		System.out.println("Alice's Public Key in Base64 :" + pubkey_Alice);
		System.out.println("Send Public Key to Client....");
		out.write(party_Alice.getPublicKeyBytes());

	    
		String ReceiveData = Base64Coder.encodeLines(receivedMsg);
		String pubkey_Bob = ReceiveData;
		System.out.println("Public Key from Bob In BASE64 ");
		System.out.println(ReceiveData);
		System.out.println("*********************************************");
		System.out.println("Public Key of Alice In BASE64");
		System.out.println(pubkey_Alice);
		
		party_Alice.doFinalPhase(receivedMsg);
		String secreteKey_Alice 	= Base64Coder.encodeLines(party_Alice.showSharedSecret());
		
		System.out.println("Shared Secret In Base64");
		System.out.println(secreteKey_Alice);
		
	    System.out.println("waiting for ciphertext from client.");
	    while (in.available() == 0) {}
	    System.out.println("Receive Public Key from Client");
	    byte[] ciphertext = new byte[in.available()];
	    in.read(ciphertext);
		
		System.out.println("Receive Cipher Text From Bob");
		byte[] encryptFile = ciphertext;
		System.out.println("LENGTH of encryptFile : " + encryptFile.length);

		MessageDigest hash_Alice = MessageDigest.getInstance("SHA-256");
		hash_Alice.update(party_Alice.showSharedSecret());
		for(int i = 0; i<1002;i++){
			hash_Alice.update(hash_Alice.digest());
		}
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom2 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom2.setSeed(hash_Alice.digest());
		generator.init(256,secureRandom2);
		SecretKey Alice_AES = generator.generateKey();
		
		byte[] IV_Alice = new byte[12];
				for(int i = 0; i<50;i++){
			hash_Alice.update(hash_Alice.digest());
		}
		hash_Alice.update(party_Alice.showSharedSecret());
		byte[] IV2 = hash_Alice.digest();
		System.arraycopy(IV2, 0, IV_Alice, 0, 12);
		
		int length_Alice = Alice_AES.getEncoded().length;
		byte[] IVandKey_Alice = new byte[12+length_Alice];
		System.arraycopy(IV_Alice, 0, IVandKey_Alice, 0, 12);
		System.arraycopy(Alice_AES.getEncoded(), 0, IVandKey_Alice, 12, length_Alice);
		FileOutputStream fos = new FileOutputStream("A-AES.txt");
		fos.write(Base64Coder.encodeLines(IVandKey_Alice).getBytes());
		fos.close();
		System.out.println();
		

		

		

		byte[] plaintext = party_Alice.decrypt(IV_Alice,Alice_AES,encryptFile);
		out.write(plaintext);
		in.close();
		out.close();
		fos = new FileOutputStream("De-cipher.txt");
		fos.write(plaintext);
		fos.close();
		
		
	}
	/*
	private static byte[] Receive_Send(byte[] Msg) throws IOException
	{
		ServerSocket serverSocket = new ServerSocket(port);
	      
	    Socket messageSocket = serverSocket.accept();
	    OutputStream out = messageSocket.getOutputStream();
	    InputStream in = messageSocket.getInputStream();
	    while (in.available() == 0) {}
	    byte[] receivedMsg = new byte[in.available()];
	    in.read(receivedMsg);
	    out.write();
	    out.close();
	    in.close();

	}*/
}
