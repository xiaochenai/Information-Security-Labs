


import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import biz.source_code.base64Coder.Base64Coder;

public class MultiUserServerThread extends Thread
{	
	
	private DatagramSocket socket = null;
	private static PrivateKey RSAPrivateKey;
	private static PublicKey  RSAPublicKey;
	private static PublicKey  PublicKey_Alice;

	private static byte[] context;
	private static byte[] ciphertext;
	private static byte[] plaintext;
	private static byte[] WrappedKey;
	private static byte[] AESKey2;
	private static byte[] decryptKey2;
	private static byte[] SigtoVerify;
	private static byte[] IV = new byte[12];
	private static byte[] AESKey1;
	private static SecretKey Key1;
	private static SecretKey Key2;
	private static DatagramSocket serverSocket;
	private static InetAddress clientIPAddress;
	private static int port;
	private static boolean verifies = false;

	public MultiUserServerThread( DatagramSocket socket )
	{
		this.socket = socket;
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
	public void run()
	{	
		try{

	
		    
			byte[] receivebuf = new byte[4096];
			byte[] sendbuf;
			
			DatagramPacket packet = new DatagramPacket(receivebuf,receivebuf.length);
			geneRSAKey GeneRSAKey = new geneRSAKey();
			RSAPrivateKey = GeneRSAKey.getPrivateKey();
			RSAPublicKey  = GeneRSAKey.getPublicKey();
			//save key pair to File
			try{
				GeneRSAKey.savePrivateKey();
				GeneRSAKey.savePublicKey();
			}catch(IOException e){}
			//exchange public key with Alice
			socket.receive(packet);
			
			String ReceiveData = new String(receivebuf,0,packet.getLength());
			String pubkey_Alice = ReceiveData;
			System.out.println("INDATA " + pubkey_Alice);
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey_Alice = keyFactory.generatePublic(
	                new X509EncodedKeySpec(Base64Coder.decodeLines(pubkey_Alice)));
			
			sendbuf = Base64Coder.encodeLines(RSAPublicKey.getEncoded()).getBytes();
			System.out.println("OUTDATA In Base64 " + Base64Coder.encodeLines(RSAPublicKey.getEncoded()));
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			try
			{
				socket.send(packet);
			}catch(IOException e){}
			
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			
			MessageDigest hash_Bob = MessageDigest.getInstance("SHA-256");
			byte[] AliceandBob = new byte[PublicKey_Alice.getEncoded().length+RSAPublicKey.getEncoded().length];
			System.arraycopy(RSAPublicKey.getEncoded(), 0, AliceandBob, 0, RSAPublicKey.getEncoded().length);
			System.arraycopy(PublicKey_Alice.getEncoded(), 0, AliceandBob, RSAPublicKey.getEncoded().length, PublicKey_Alice.getEncoded().length);
			
			hash_Bob.update(AliceandBob);
			for(int i = 0; i<1000;i++){
				hash_Bob.update(hash_Bob.digest());
			}
			byte[] digest = hash_Bob.digest();
			byte[] IV1 = new byte[16];
			System.arraycopy(digest, 0, IV1, 0, 16);
			//to prove that Bob have the correspond private key
			hash_Bob.update(AliceandBob);
			System.out.println("AliceandBob" + Base64Coder.encodeLines(AliceandBob));
			for(int i = 0; i<50;i++){
				hash_Bob.update(hash_Bob.digest());
			}
			digest = hash_Bob.digest();
			String compare1 = Base64Coder.encodeLines(digest);
			System.out.println("compare1 :  " + compare1);
			
			Cipher cipher;
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, RSAPrivateKey);
			byte[] cipherData = cipher.doFinal(compare1.getBytes());
			System.out.println("OUT Ss: " + Base64Coder.encodeLines(cipherData));
			sendbuf = Base64Coder.encodeLines(cipherData).getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			
			try
			{
				socket.send(packet);
			}catch(IOException e){}
			
			//receive ciphertext from Alice
			ServerSocket ss = new ServerSocket(3000);
			Socket asocket = ss.accept();
			BufferedInputStream bis = new BufferedInputStream(asocket
					.getInputStream());
			byte[] bFileName = new byte[255];
			int len = bis.read(bFileName);
			String fileName = new String(bFileName, 0, len).trim();
			byte[] bytes = new byte[1024];
			FileOutputStream fos = new FileOutputStream("ciphertext_Bob.txt");
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			len = 0;
			while ((len = bis.read(bytes)) != -1) {
				bos.write(bytes, 0, len);
			}
			bos.close();
			fos.close();
			bis.close();
			asocket.close();
			
			

			//response
			
			
			String response;
			
			//receive wrapped AESKEY1 and IV from Alice
	
		    System.out.println("continue");
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			ReceiveData = new String(receivebuf,0,packet.getLength());
			WrappedKey = Base64Coder.decodeLines(ReceiveData);
			
			//response
			response = "wrapped key received";
			
			sendbuf = response.getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			socket.send(packet);
			
			//receive encrypted AESKey2 from Alice
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			ReceiveData = new String(receivebuf,0,packet.getLength());
			AESKey2 = Base64Coder.decodeLines(ReceiveData);
			
			//response
			response = "AESKey2 received";
			
			sendbuf = response.getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			socket.send(packet);
			
			//receive Alice's signature
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			ReceiveData = new String(receivebuf,0,packet.getLength());
			SigtoVerify = Base64Coder.decodeLines(ReceiveData);
			//response
			response = "Signature received";
			
			sendbuf = response.getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			socket.send(packet);
			
			
			//get all received information, and put them into a array to verify the signature
			ciphertext = getBytesFromFile(new File("ciphertext_Bob.txt"));
			context = new byte[ciphertext.length+WrappedKey.length+AESKey2.length];
			System.arraycopy(ciphertext, 0, context, 0, ciphertext.length);
			System.arraycopy(WrappedKey, 0, context, ciphertext.length, WrappedKey.length);
			System.arraycopy(AESKey2, 0, context, WrappedKey.length+ciphertext.length, AESKey2.length);
			
			//try to verify Alice's signature
			hash_Bob.update(context);
			digest = hash_Bob.digest();
			
			Signature sig = Signature.getInstance("SHA256withRSA");
			try {
				sig.initVerify(PublicKey_Alice);
				sig.update(digest);
				verifies = sig.verify(SigtoVerify);
				System.out.println("signature verifies: " + verifies);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if(verifies){
				
				try {
					cipher = Cipher.getInstance("RSA");
					cipher.init(Cipher.DECRYPT_MODE, RSAPrivateKey);
					decryptKey2 = cipher.doFinal(AESKey2);
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				//get Key2
				Key2 = new SecretKeySpec(decryptKey2, "AES");
				//unwrap the wrapped key then get the Key1 and IV
				unWrap unwrap = new unWrap(WrappedKey,Key2,IV1);
				byte[] current = unwrap.doUnWrap();
				System.arraycopy(current, 0, IV, 0, 12);
				AESKey1 = new byte[current.length-12];
				System.arraycopy(current, 12, AESKey1, 0, current.length-12);
				
				Key1 = new SecretKeySpec(AESKey1, "AES");
				
				DecryptFile decryptFile = new DecryptFile(Key1,IV,ciphertext);
				plaintext = decryptFile.decryption();
				System.out.println("Saving plaintext to file........");
				decryptFile.SavePlaintexttoFile();
			}
			
		}catch(IOException e){} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
	
	}
	public static String getStringFromFile(String filename) throws IOException {

		BufferedReader reader = new BufferedReader(new FileReader(filename));
		StringBuilder stringBuilder = new StringBuilder();
		String line = null;

		while ((line = reader.readLine()) != null) {
			stringBuilder.append(line);
		}

		return stringBuilder.toString();
	}


	
}