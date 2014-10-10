

import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
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
		try{
			byte[] receivebuf = new byte[4096];
			byte[] sendbuf;
			
			DatagramPacket packet = new DatagramPacket(receivebuf,receivebuf.length);
			
			
			
			ECGenParameterSpec ecParamSpec_1 = new ECGenParameterSpec("P256");
			EcdhKeyAgreementParty party_Alice = new EcdhKeyAgreementParty("Alice",ecParamSpec_1);
			System.out.println("This is Alice !");
			
			System.out.println("Generate Public key and Private key of Alcie");
			String pubkey_Alice 	= Base64Coder.encodeLines(party_Alice.getPublicKeyBytes());
			String priv_Alice		= Base64Coder.encodeLines(party_Alice.getPrivateKeyBytes());
			socket.receive(packet);
			
			String ReceiveData = new String(receivebuf,0,packet.getLength());
			String pubkey_Bob = ReceiveData;
			System.out.println("Public Key from Bob In BASE64 ");
			System.out.println(ReceiveData);
			System.out.println("*********************************************");
			System.out.println("Public Key of Alice In BASE64");
			System.out.println(pubkey_Alice);
			
			party_Alice.doFinalPhase(Base64Coder.decodeLines(pubkey_Bob));
			String secreteKey_Alice 	= Base64Coder.encodeLines(party_Alice.showSharedSecret());
			
			System.out.println("Shared Secret In Base64");
			System.out.println(secreteKey_Alice);
			
			sendbuf = pubkey_Alice.getBytes();
			packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
			
			
			try
			{
				socket.send(packet);
			}catch(IOException e){}
			while(true)
			{
			//attention: the receive buffer is just 1024byte, so can not handle data bigger than 1024 bytes

			
			try{
				packet = new DatagramPacket(receivebuf,receivebuf.length);
				socket.receive(packet);
				ReceiveData = new String(receivebuf,0,packet.getLength());
				System.out.println("Receive Cipher Text From Bob");
				System.out.println("ReceiveData");
				System.out.println(ReceiveData);
				byte[] encryptFile = Base64Coder.decodeLines(ReceiveData);
				System.out.println("LENGTH of encryptFile : " + encryptFile.length);
				//PrintBuffer.printBuffer(encryptFile);
				MessageDigest hash_Alice = MessageDigest.getInstance("SHA-256");
				hash_Alice.update(party_Alice.showSharedSecret());
				for(int i = 0; i<1000;i++){
					hash_Alice.update(hash_Alice.digest());
				}
				KeyGenerator generator = KeyGenerator.getInstance("AES");
				SecureRandom secureRandom2 = SecureRandom.getInstance("SHA1PRNG");
				secureRandom2.setSeed(hash_Alice.digest());
				generator.init(256,secureRandom2);
				SecretKey Alice_AES = generator.generateKey();
				
				byte[] IV_Alice = new byte[12];
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
				

				

				

				byte[] de_cipher = party_Alice.decrypt(IV_Alice,Alice_AES,encryptFile);
				String decipher = Base64Coder.encodeLines(de_cipher);
				byte[] newsendbuff;
				newsendbuff = decipher.getBytes();
				packet = new DatagramPacket(newsendbuff,newsendbuff.length,packet.getAddress(),packet.getPort());
				
				try
				{
					socket.send(packet);
				}catch(IOException e){}
				
				fos = new FileOutputStream(new File("de-cipher.txt"));
				fos.write(de_cipher);
				fos.close();
				
			}catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			}
		}catch(Exception e){
			
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