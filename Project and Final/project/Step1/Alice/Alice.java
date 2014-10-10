
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;



import biz.source_code.base64Coder.Base64Coder;


public class Alice {
	private static int Serverport;
	private static DatagramSocket socket;
	private static InetAddress ServerIpAddress;

	private static PrivateKey RSAPrivateKey;
	private static PublicKey  RSAPublicKey;
	private static SecretKey  AESKey;
	private static byte[] IV;

	private static byte[] ciphertext;
	private static byte[] AESKeyandIV;
	private static byte[] encyptKey2;
	private static boolean PrivateKeyExist = false;
	private static SecureRandom securerandom;
	private static String Send_Receive(String Datain) throws IOException
	{
		byte[] SendData = Datain.getBytes();
		DatagramPacket sendPacket = new DatagramPacket(SendData,SendData.length,ServerIpAddress,Serverport);
		socket.send(sendPacket);
		
		byte[] receivebuf = new byte[2048];
		DatagramPacket receivePacket = new DatagramPacket(receivebuf,receivebuf.length);
		socket.receive(receivePacket);
		String str = new String(receivebuf,0,receivePacket.getLength());
		return str;	
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
	public static void main(String[] args) throws Exception {

		
		System.out.println("enter server IP Address : ");
		String ServerIp = easyscanner.nextString();
		ServerIpAddress = InetAddress.getByName(ServerIp);
		System.out.println("enter the port number");
		String port = easyscanner.nextString();
		Serverport = Integer.parseInt(port);
		socket = new DatagramSocket();
		

		
		System.out.println("Generating RSA public key and private key..........");
		
		geneRSAKey GeneRSAKey = new geneRSAKey();
		RSAPrivateKey = GeneRSAKey.getPrivateKey();
		RSAPublicKey  = GeneRSAKey.getPublicKey();
		
		System.out.println("Save private key and public key to file");
		try{
		GeneRSAKey.savePrivateKey();
		GeneRSAKey.savePublicKey();
		}catch(IOException e){}
		
		//get AES256 key and IV, then encrypt the file
		System.out.println("Generating AES256 Key and IV......");
		try {
			GeneAESKeyandIV geneAESKeyandIV = new GeneAESKeyandIV();
			AESKey = geneAESKeyandIV.getKey();
			IV = geneAESKeyandIV.getIV();
			System.out.println();
			System.out.println("Saving AESKey and IV to File");
			AESKeyandIV = geneAESKeyandIV.GetKeyandIV();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("encrypting File........");
		EncryptFile encryptFile = new EncryptFile(AESKey,IV,getBytesFromFile(new File("plain.txt")));
		ciphertext = encryptFile.encryption();
		
		System.out.println("Saveing ciphertext to ciphertext.txt");
		encryptFile.SaveCiphertoFile();
		//Key transport, first exchange public key with Bob
		System.out.println("Exchange Public Key with Bob");
		
		String BobResponse = Send_Receive( Base64Coder.encodeLines(RSAPublicKey.getEncoded()));
		
		System.out.println("OUTDATA in BAse64 : " + Base64Coder.encodeLines(RSAPublicKey.getEncoded()));
		
		System.out.println("InDATA in Base64 : "  + BobResponse);
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA","JsafeJCE");
		PublicKey peerPubKey = keyFactory.generatePublic(
                new X509EncodedKeySpec(Base64Coder.decodeLines(BobResponse)));
		MessageDigest hash_Alice = MessageDigest.getInstance("SHA-256");
		byte[] AliceandBob = new byte[peerPubKey.getEncoded().length+RSAPublicKey.getEncoded().length];
		System.arraycopy(peerPubKey.getEncoded(), 0, AliceandBob, 0, peerPubKey.getEncoded().length);
		System.arraycopy(RSAPublicKey.getEncoded(), 0, AliceandBob, peerPubKey.getEncoded().length, RSAPublicKey.getEncoded().length);
		
		hash_Alice.update(AliceandBob);
		for(int i = 0; i<1000;i++){
			hash_Alice.update(hash_Alice.digest());
		}
		byte[] digest = hash_Alice.digest();
		byte[] IV1 = new byte[16];
		System.arraycopy(digest, 0, IV1, 0, 16);
		//generate a AES key2 to encrypt AES key
		KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
		securerandom = new SecureRandom();
		securerandom.setSeed(System.nanoTime());
		keygenerator.init(256, securerandom);
		Key key2 = keygenerator.generateKey();
		
		Wrap wrap = new Wrap(AESKeyandIV,key2,IV1);
		byte[] encryptKey = wrap.doWrap();
		
		Cipher cipher;
	
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, peerPubKey);
			encyptKey2 = cipher.doFinal(key2.getEncoded());
		} catch (NoSuchPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
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
		
		//make sure Bob have the privateKey correspond to the public key that Alice received
		BobResponse = Send_Receive(" ");
		System.out.println("AliceandBob" + Base64Coder.encodeLines(AliceandBob));
		hash_Alice.update(AliceandBob);
		for(int i = 0; i<50;i++){
			hash_Alice.update(hash_Alice.digest());
		}
		digest = hash_Alice.digest();
		
		String compare1 = Base64Coder.encodeLines(digest);
		System.out.println("compare1 :  " + compare1);
		
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, peerPubKey);
			
			System.out.println("in SS: " + BobResponse);
			
			byte[] cipherData = cipher.doFinal(Base64Coder.decodeLines(BobResponse));
			
			String compare2 = new String(cipherData,0,cipherData.length);
			if(compare1.equals(compare2)){
				PrivateKeyExist = true;
				System.out.println("Bob has the Private Key");
			}
			else
				System.out.println("DO NOT EQUAL");
				
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
		
		if(PrivateKeyExist){
			//send ciphertext to Bob use TCP
			File file = new File("ciphertext");
			String fileName = "ciphertext";
			Socket socket = new Socket("127.0.0.1", 3000);
			FileInputStream fs = new FileInputStream("ciphertext.txt");
			byte[] bytes = new byte[1024];
			BufferedOutputStream bos = new BufferedOutputStream(socket
					.getOutputStream());

			bos.write(fileName.getBytes());
			bos.flush();
			int len = 0;
			while ((len = fs.read(bytes)) != -1) {
				bos.write(bytes, 0, len);
			}
			bos.close();
			fs.close();
			
			socket.close();
			System.out.println("finish transmission");
			
			System.out.println("ciphertext length" + ciphertext.length);
//			out.write(ciphertext);
//			out.close();
//			in.close();
		    String Response ;
			System.out.println("continue");
			//send encrypted AESKey1 and IV to Bob, this key is used to decrypt ciphertext
			Response = Send_Receive(Base64Coder.encodeLines(encryptKey));
			System.out.println("Bob : " + Response);
			
			//send encrypted AESkey2 to Bob, this key is used to decrypt encrypted AESKey1 and IV
			Response = Send_Receive(Base64Coder.encodeLines(encyptKey2));
			System.out.println("Bob : " + Response);
			
			
			//sign the signature for transportation 
			
			//get the context that send to Bob
			byte[] context = new byte[ciphertext.length+encryptKey.length+encyptKey2.length];
			System.arraycopy(ciphertext, 0, context, 0, ciphertext.length);
			System.arraycopy(encryptKey, 0, context, ciphertext.length, encryptKey.length);
			System.arraycopy(encyptKey2, 0, context, ciphertext.length+encryptKey.length, encyptKey2.length);
			
			hash_Alice.update(context);
			digest = hash_Alice.digest();
			Signature dsa = Signature.getInstance("SHA256withRSA");
			
			dsa.initSign(RSAPrivateKey);
			dsa.update(digest);
			byte[] AliceSig = dsa.sign();
			
			//send Alice's Signature to Bob
			
			Response = Send_Receive(Base64Coder.encodeLines(AliceSig));
			System.out.println("BOB : " + Response);
		}

		
		
		

		
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
