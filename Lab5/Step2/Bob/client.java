import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;



import biz.source_code.base64Coder.Base64Coder;


public class client {
	private static int Serverport;
	private static DatagramSocket socket;
	private static InetAddress ServerIpAddress;
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
		
		ECGenParameterSpec ecParamSpec_1 = new ECGenParameterSpec("P256");
		EcdhKeyAgreementParty party_Bob = new EcdhKeyAgreementParty("Bob",ecParamSpec_1);
		System.out.println("This is Bob !");
		
		System.out.println("Generate Public key and Private key of Bob");
		String pubkey_Bob 	= Base64Coder.encodeLines(party_Bob.getPublicKeyBytes());
		String priv_Bob		= Base64Coder.encodeLines(party_Bob.getPrivateKeyBytes());
		
		System.out.println("Bob's PublicKey in BASE64");
		System.out.println(pubkey_Bob);
		System.out.println("************************************");
		String pubkey_Alice = Send_Receive(pubkey_Bob);
		System.out.println("Alice's PublicKey in Base64");
		System.out.println(pubkey_Alice);
		
		party_Bob.doFinalPhase(Base64Coder.decodeLines(pubkey_Alice));
		
		String secreteKey_Bob 	= Base64Coder.encodeLines(party_Bob.showSharedSecret());
		
		System.out.println("Shared Secret In Base64");
		System.out.println(secreteKey_Bob);
		
		MessageDigest hash_Bob = MessageDigest.getInstance("SHA-256");
		hash_Bob.update(party_Bob.showSharedSecret());
		for(int i = 0; i<1000;i++){
			hash_Bob.update(hash_Bob.digest());
		}
		
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom1.setSeed(hash_Bob.digest());
		generator.init(256, secureRandom1);
		SecretKey Bob_AES = generator.generateKey();


		byte[] IV_Bob = new byte[12];
		hash_Bob.update(party_Bob.showSharedSecret());
		byte[] IV1 = hash_Bob.digest();
		System.arraycopy(IV1, 0, IV_Bob, 0, 12);
		byte[] plaintext = getBytesFromFile(new File("plaintext.txt"));
		byte[] ciphertext= party_Bob.encrypt(IV_Bob,Bob_AES,plaintext);


		int length_Bob = Bob_AES.getEncoded().length;
	    byte[] IVandKey_Bob = new byte[12+length_Bob];
		System.arraycopy(IV_Bob, 0, IVandKey_Bob, 0, 12);
		System.arraycopy(Bob_AES.getEncoded(), 0, IVandKey_Bob, 12, length_Bob);
		
		FileOutputStream fos = new FileOutputStream("B-AES.txt");
		fos.write(Base64Coder.encodeLines(IVandKey_Bob).getBytes());
		fos.close();
		
		fos = new FileOutputStream("cipher.txt");
		fos.write(ciphertext);
		fos.close();
		

		// test for byte[] to String
//		String a = new String(data);
//		for(int i=0;i<data.length;i++)
//		{
//			System.out.print(data[i]+" ");
//		}
//		System.out.println();
//		for(int i=0;i<a.getBytes().length;i++)
//		{
//			System.out.print(a.getBytes()[i] + " ");
//		}
		String encryptFile = Base64Coder.encodeLines(ciphertext);
//		System.out.println(encryptFile);
		

		byte[] decipher = Base64Coder.decodeLines(Send_Receive(encryptFile));
		
		//System.out.println("Receive de-cipher text from Alice");
		//PrintBuffer.printBuffer(decipher);
		

		
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
