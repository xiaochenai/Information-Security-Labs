import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
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
	private static void Send_Receive(String Datain) throws IOException
	{
		byte[] SendData = Datain.getBytes();
		DatagramPacket sendPacket = new DatagramPacket(SendData,SendData.length,ServerIpAddress,Serverport);
		socket.send(sendPacket);
		
		
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
		System.out.println("Server IP :" + ServerIp);
		System.out.println("Server port : " + port);
		
		// Create a secure random number generator
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(System.nanoTime());
		// Get 1024 random bits
		byte[] bytes = new byte[1024/8];
		sr.nextBytes(bytes);

		// save the random number in base64 format
		String encodedString = Base64Coder.encodeLines(bytes, 0, bytes.length, 76, "");
		FileOutputStream output = new FileOutputStream("RAND.txt");
		output.write(encodedString.getBytes());
		output.close();
		
		String publicKeyString = getStringFromFile("Kpublic.txt");
		byte[] publicKeyByte = Base64Coder.decode(publicKeyString);
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyByte);
		PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
		String randString = getStringFromFile("RAND.txt");
		byte[] rand = Base64Coder.decode(randString);

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		System.out.println("rand length :" + rand.length);
		byte[] cipherData = cipher.doFinal(rand);

		String encodedString1 = Base64Coder.encodeLines(cipherData, 0, cipherData.length, 76, "");
		FileOutputStream output1 = new FileOutputStream("En-Ran.txt");
		output1.write(encodedString1.getBytes());
		output1.close();
		
		Send_Receive(encodedString1);
		System.out.println("Send random number in BASE64: " + randString);
		
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		SecureRandom ksr = SecureRandom.getInstance("SHA1PRNG");
		ksr.setSeed(rand);
		keyGen.init(256,ksr);
		SecretKey key = keyGen.generateKey();
		byte[] KeyByte = key.getEncoded();
		
		String KeyString = new String(KeyByte);
	    
	    FileOutputStream output11 = new FileOutputStream("C-AES-Key.txt");
		String decodedString1 = Base64Coder.encodeString(KeyString);
		output11.write(decodedString1.getBytes());
		output11.close();	
		
	}
}
