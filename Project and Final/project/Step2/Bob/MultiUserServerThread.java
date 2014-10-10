

import java.net.*;
import java.nio.ByteBuffer;
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
import java.util.Date;

import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;


import biz.source_code.base64Coder.Base64Coder;

public class MultiUserServerThread extends Thread
{	
	
	private DatagramSocket socket = null;
	private static PrivateKey PrivateKey;
	private static PublicKey  PublicKey;
	private static PublicKey  PublicKey_Alice;
	private static KeyAgreement keyAgree;
	private static SecretKey sharedSecretKey;
	private static byte[] context;
	private static byte[] ciphertext;
	private static byte[] plaintext;
	private static byte[] WrappedKey;
	private static byte[] AESKey2;
	private static byte[] decryptKey2;
	private static byte[] SigtoVerify;
	private static byte[] IV = new byte[12];
	private static byte[] AESKey1;
	private static byte[] ShareSecret;
	private static SecretKey KeyWrapKey;
	private static SecretKey Key1;
	private static SecretKey Key2;
	private static PublicKey SignatureKey;
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
			
			//generate constant and ephemeral key pair for Alice
			ECGenParameterSpec agreedParameters = new ECGenParameterSpec("K571");
			geneKeyPair GeneKeyPair = new geneKeyPair(agreedParameters);
			PrivateKey = GeneKeyPair.getPrivateKey();
			PublicKey  = GeneKeyPair.getPublicKey();
			GeneKeyPair.savePrivateKey();
			GeneKeyPair.savePublicKey();
			keyAgree = KeyAgreement.getInstance("ECDH", "JsafeJCE");
			keyAgree.init(GeneKeyPair.getPrivateKey(), agreedParameters);
			System.out.println("This is Bob !");
			
			
			
			socket.receive(packet);
			String ReceiveData = new String(receivebuf,0,packet.getLength());
			String pubkey_Alice = ReceiveData;
			System.out.println("IN : " + pubkey_Alice);
			KeyFactory keyFactory = KeyFactory.getInstance("ECDH","JsafeJCE");
			PublicKey_Alice = keyFactory.generatePublic(
	                new X509EncodedKeySpec(Base64Coder.decodeLines(pubkey_Alice)));
			keyAgree.doPhase(PublicKey_Alice, true);
			
			ShareSecret = keyAgree.generateSecret();
			
			SecretKeyFactory aesFac = SecretKeyFactory.getInstance("AES", "JsafeJCE");
			
			
			String shareSecret = Base64Coder.encodeLines(ShareSecret);
			
			System.out.println("ShareSecrete In Base64 : " + shareSecret);
			
			sendbuf = Base64Coder.encodeLines(PublicKey.getEncoded()).getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			try
			{
				socket.send(packet);
			}catch(IOException e){}
			
			
			//make sure Alice and Bob Have same shared secret
			SecretKey secretekey = new SecretKeySpec(ShareSecret,"HmacSHA256");
			Mac mac = Mac.getInstance(secretekey.getAlgorithm());
			mac.init(secretekey);
			
			
			
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			ReceiveData = new String(receivebuf,0,packet.getLength());
			byte[] digest_mac = mac.doFinal(Base64Coder.decodeLines(ReceiveData));
			
			sendbuf = Base64Coder.encodeLines(digest_mac).getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			try
			{
				socket.send(packet);
			}catch(IOException e){}
			
			
			//generate KeyWrappingKey
			MessageDigest hash_Bob = MessageDigest.getInstance("SHA-256");
			hash_Bob.update(ShareSecret);
			for(int i = 0; i<100;i++){
				hash_Bob.update(hash_Bob.digest());
			}
			
			byte[] digest3 = hash_Bob.digest();
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
			secureRandom1.setSeed(digest3);
			generator.init(256, secureRandom1);
			KeyWrapKey = generator.generateKey();
			byte[] WrapIV = new byte[16];
			System.arraycopy(digest3, 0, WrapIV, 0, 16);
			//System.out.println("IV " + Base64Coder.encodeLines(WrapIV));
			
			//receive wrapped key
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			ReceiveData = new String(receivebuf,0,packet.getLength());
			WrappedKey = Base64Coder.decodeLines(ReceiveData);
			//send nonce to Alice
			byte[] nonce_Bob = new byte[256];
			secureRandom1 = SecureRandom.getInstance("SHA1PRNG","JsafeJCE");
			secureRandom1.setSeed(GeneTimeSeed());
			secureRandom1.nextBytes(nonce_Bob);
			sendbuf = Base64Coder.encodeLines(nonce_Bob).getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			try
			{
				socket.send(packet);
			}catch(IOException e){}
			
			//receive nonce of Alice
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			ReceiveData = new String(receivebuf,0,packet.getLength());
			byte[] nonce_Alice = Base64Coder.decodeLines(ReceiveData);
			
			//send back nothing to Alice
			sendbuf = Base64Coder.encodeLines(nonce_Bob).getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			try
			{
				socket.send(packet);
			}catch(IOException e){}
			
			//receive MacKey from Alice
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			ReceiveData = new String(receivebuf,0,packet.getLength());
			secretekey = new SecretKeySpec(Base64Coder.decodeLines(ReceiveData),"HmacSHA256");
			mac = Mac.getInstance(secretekey.getAlgorithm());
			mac.init(secretekey);
			System.out.println("secretekey : " + Base64Coder.encodeLines(secretekey.getEncoded()));
			
			//generate MacTag
			byte[] MacMsg = new byte[nonce_Alice.length+WrappedKey.length+nonce_Bob.length+"Alice".getBytes().length+"Bob".getBytes().length];
			System.arraycopy("Alice".getBytes(), 0, MacMsg, 0, "Alice".getBytes().length);
			System.arraycopy("Bob".getBytes(), 0, MacMsg, "Alice".getBytes().length, "Bob".getBytes().length);
			System.arraycopy(nonce_Alice, 0, MacMsg, "Alice".getBytes().length+"Bob".getBytes().length, nonce_Alice.length);
			System.arraycopy(nonce_Bob, 0, MacMsg, "Alice".getBytes().length+"Bob".getBytes().length+nonce_Alice.length, nonce_Bob.length);
			System.arraycopy(WrappedKey, 0, MacMsg, "Alice".getBytes().length+"Bob".getBytes().length+nonce_Alice.length+nonce_Bob.length, WrappedKey.length);
			//send mactag to Alice;
			byte[] MacTag = mac.doFinal(MacMsg);
			sendbuf = Base64Coder.encodeLines(MacTag).getBytes();
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
			
			//receive Signature public key from Alice
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			ReceiveData = new String(receivebuf,0,packet.getLength());
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64Coder.decodeLines(ReceiveData));
			keyFactory = KeyFactory.getInstance("ECDSA");
			SignatureKey = keyFactory.generatePublic(pubKeySpec);
			//response
			String response = "Signature Public Key received";
			sendbuf = response.getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			try
			{
				socket.send(packet);
			}catch(IOException e){}
			
			//receive Signature From Alice
			packet = new DatagramPacket(receivebuf,receivebuf.length);
			socket.receive(packet);
			ReceiveData = new String(receivebuf,0,packet.getLength());
			String signature = ReceiveData;
			//response
			response = "Signature received";
			sendbuf = response.getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			try
			{
				socket.send(packet);
			}catch(IOException e){}
			
			//verify signature
			Signature ecdsaVerifier = null;
			ecdsaVerifier = Signature.getInstance("SHA256/ECDSA", "JsafeJCE");
			ecdsaVerifier.initVerify(SignatureKey);
			ciphertext = getBytesFromFile(new File("ciphertext_Bob.txt"));
			
			byte[] input = new byte[ciphertext.length + WrappedKey.length ];
			System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
			System.arraycopy(WrappedKey, 0, input, ciphertext.length, WrappedKey.length);
			hash_Bob.update(input);
			byte[] message = hash_Bob.digest();
			ecdsaVerifier.update(message, 0, message.length);
			
			boolean verified = ecdsaVerifier.verify(Base64Coder.decodeLines(signature));
			
			if(verified)
				System.out.println("Signature Verified");
			else
				System.out.println("Signature Verified Failed");
			//start decryption process
			if(verified){
				//first unwrap the AESKey and IV
				unWrap unwrap = new unWrap(WrappedKey,KeyWrapKey,WrapIV);
				byte[] current = unwrap.doUnWrap();
				System.arraycopy(current, 0, IV, 0, 12);
				AESKey1 = new byte[current.length-12];
				System.arraycopy(current, 12, AESKey1, 0, current.length-12);
				
				Key1 = new SecretKeySpec(AESKey1, "AES");
				
				DecryptFile decryptFile = new DecryptFile(Key1,IV,ciphertext);
				plaintext = decryptFile.decryption();
				System.out.println("Saving plaintext to file........");
				decryptFile.SavePlaintexttoFile();
				System.out.println("plaintext Saved");
				
			}
		}catch (Exception e) {
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

	
}