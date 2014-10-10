

import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import biz.source_code.base64Coder.Base64Coder;

public class MultiUserServerThread extends Thread
{	
	
	private DatagramSocket socket = null;


	public MultiUserServerThread( DatagramSocket socket )
	{
		this.socket = socket;
	}

	public void run()
	{
		while(true)
		{
		//attention: the receive buffer is just 1024byte, so can not handle data bigger than 1024 bytes
		byte[] receivebuf = new byte[2048];
		
		
		DatagramPacket packet = new DatagramPacket(receivebuf,receivebuf.length);
		
		try{
			
			socket.receive(packet);
			
			String ReceiveData = new String(receivebuf,0,packet.getLength());
			System.out.println("receive data from client:" + ReceiveData);
			
			String privateKeyString = getStringFromFile("Kprivate.txt");
			byte[] privateKeyBytes = Base64Coder.decode(privateKeyString);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

			
			byte[] eRand = Base64Coder.decode(ReceiveData);
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey2);
			byte[] cipherData = cipher.doFinal(eRand);
			
			FileOutputStream output = new FileOutputStream("DE-Ran.txt");
			String decodedString = Base64Coder.encodeLines(cipherData, 0, cipherData.length, 76, "");
			output.write(decodedString.getBytes());
			output.close();
			
			System.out.println("decrypted random number in BASE64: " + decodedString);
			System.out.println();
			String number = new String(cipherData);
			System.out.println("random number : " + number);
			
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			SecureRandom ksr = SecureRandom.getInstance("SHA1PRNG");
			ksr.setSeed(cipherData);
			keyGen.init(256,ksr);
			SecretKey key = keyGen.generateKey();
			byte[] KeyByte = key.getEncoded();
			
			String KeyString = new String(KeyByte);
		    
		    FileOutputStream output1 = new FileOutputStream("S-AES-Key.txt");
			String decodedString1 = Base64Coder.encodeString(KeyString);
			output1.write(decodedString1.getBytes());
			output1.close();	
			
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