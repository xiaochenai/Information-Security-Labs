import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import biz.source_code.base64Coder.Base64Coder;


public class Client {
	private static InetAddress server = null;
	private static int   port;
	public static void main(String[] args){
		
		
		System.out.println("Enter host's IP Address");
		String Ip = easyscanner.nextString();
		try{
			server = InetAddress.getByName(Ip);
		}catch(UnknownHostException e){
			System.out.println("Unknown Host:" + Ip);
		}
		try{
			System.out.println("Enter host's port");
			int port = easyscanner.nextInt();
			
			Socket messageSocket = new Socket(server, port);
			
			
			ECGenParameterSpec ecParamSpec_1 = new ECGenParameterSpec("P256");
			EcdhKeyAgreementParty party_Bob = new EcdhKeyAgreementParty("Bob",ecParamSpec_1);
			System.out.println("This is Bob !");
			
			System.out.println("Generate Public key and Private key of Bob");
			String pubkey_Bob 	= Base64Coder.encodeLines(party_Bob.getPublicKeyBytes());
			String priv_Bob		= Base64Coder.encodeLines(party_Bob.getPrivateKeyBytes());
			
			System.out.println("Bob's PublicKey in BASE64");
			System.out.println(pubkey_Bob);
			System.out.println("************************************");
			OutputStream out = messageSocket.getOutputStream();
		    InputStream in = messageSocket.getInputStream();
		    out.write(party_Bob.getPublicKeyBytes());
		    while (in.available() == 0) {}
		    byte[] receivedMsg = new byte[in.available()];
		    in.read(receivedMsg);

			byte[] pubkey_Alice = receivedMsg;
			System.out.println("Alice's PublicKey in Base64");
			System.out.println(Base64Coder.encodeLines(pubkey_Alice));
			
			party_Bob.doFinalPhase(pubkey_Alice);
			
			String secreteKey_Bob 	= Base64Coder.encodeLines(party_Bob.showSharedSecret());
			
			System.out.println("Shared Secret In Base64");
			System.out.println(secreteKey_Bob);
			
			MessageDigest hash_Bob = MessageDigest.getInstance("SHA-256");
			hash_Bob.update(party_Bob.showSharedSecret());
			for(int i = 0; i<1002;i++){
				hash_Bob.update(hash_Bob.digest());
			}
			
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
			secureRandom1.setSeed(hash_Bob.digest());
			generator.init(256, secureRandom1);
			SecretKey Bob_AES = generator.generateKey();


			byte[] IV_Bob = new byte[12];
						for(int i = 0; i<50;i++){
				hash_Bob.update(hash_Bob.digest());
			}
			hash_Bob.update(party_Bob.showSharedSecret());
			byte[] IV1 = hash_Bob.digest();
			System.arraycopy(IV1, 0, IV_Bob, 0, 12);
			
			byte[] plaintext = getBytesFromFile( new File("plaintext.txt"));
			byte[] ciphertext= party_Bob.encrypt(IV_Bob,Bob_AES,plaintext);


			int length_Bob = Bob_AES.getEncoded().length;
		    byte[] IVandKey_Bob = new byte[12+length_Bob];
			System.arraycopy(IV_Bob, 0, IVandKey_Bob, 0, 12);
			System.arraycopy(Bob_AES.getEncoded(), 0, IVandKey_Bob, 12, length_Bob);
			
			FileOutputStream fos = new FileOutputStream("B-AES.txt");
			fos.write(Base64Coder.encodeLines(IVandKey_Bob).getBytes());
			fos.close();
			
//			String encryptFile = Base64Coder.encodeLines(ciphertext);
//			System.out.println(encryptFile);
			

			out.write(ciphertext);
		    while (in.available() == 0) {}
		    receivedMsg = new byte[in.available()];
		    in.read(receivedMsg);
		    System.out.println("plaintext received from Alice: ");
	        PrintBuffer.printBuffer(receivedMsg);
			

		}catch(Exception e){}
	}
	private static byte[] Send_Receive(byte[] Msg) throws IOException
	{
		Socket messageSocket = new Socket("172.17.104.100", 8888);
		OutputStream out = messageSocket.getOutputStream();
	    InputStream in = messageSocket.getInputStream();
	    out.write(Msg);
	    while (in.available() == 0) {}
	    byte[] receivedMsg = new byte[in.available()];
	    in.read(receivedMsg);
	    out.close();
	    in.close();
	    return receivedMsg;

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
