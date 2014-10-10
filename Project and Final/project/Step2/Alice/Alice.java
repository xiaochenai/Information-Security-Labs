
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
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
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

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


public class Alice {
	private static int Serverport;
	private static DatagramSocket socket;
	private static InetAddress ServerIpAddress;
	private static byte[] sharedSecret;
	private static PrivateKey SignaturePrivateKey;
	private static PublicKey  SignaturePublicKey;
	private static PrivateKey EmPrivateKey;
	private static PublicKey EmPublicKey;
	private static PublicKey PublicKey_Bob;
	private static SecretKey  AESKey;
	private static byte[] AESandIV;
	private static byte[] IV;
	private static SecretKey KeyWrapKey;
	private static KeyAgreement keyAgree;
	private static byte[] WrappedKey;

	private static byte[] ciphertext;

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
		

		//generate constant key pair for Alice
		System.out.println("Generating Constant Key Pair for Alice..........");
		ECGenParameterSpec agreedParameters = new ECGenParameterSpec("K571");

		
		//generate Ephemeral key pair for Alice
		System.out.println("Generating Ephemeral Key Pair for ");
		
		geneKeyPair EmGeneKeyPair = new geneKeyPair(agreedParameters);
		EmPrivateKey = EmGeneKeyPair.getPrivateKey();
		EmPublicKey  = EmGeneKeyPair.getPublicKey();
		EmGeneKeyPair.savePrivateKey();
		EmGeneKeyPair.savePublicKey();
		keyAgree = KeyAgreement.getInstance("ECDH", "JsafeJCE");
		keyAgree.init(EmGeneKeyPair.getPrivateKey(), agreedParameters);
		
		System.out.println("Exchagne Public Key with Bob");
		String pub_key = Send_Receive(Base64Coder.encodeLines(EmPublicKey.getEncoded()));
		KeyFactory keyFactory = KeyFactory.getInstance("ECDH","JsafeJCE");
		PublicKey peerPubKey = keyFactory.generatePublic(
                new X509EncodedKeySpec(Base64Coder.decodeLines(pub_key)));
		
		keyAgree.doPhase(peerPubKey, true);
		
		sharedSecret = keyAgree.generateSecret();
		
		SecretKeyFactory aesFac = SecretKeyFactory.getInstance("AES", "JsafeJCE");
		
		
		System.out.println("SHARED Secrete in BAse64 : " + Base64Coder.encodeLines(sharedSecret));

		SecretKey secretekey = new SecretKeySpec(sharedSecret,"HmacSHA256");
		Mac mac = Mac.getInstance(secretekey.getAlgorithm());
		mac.init(secretekey);
		SecureRandom rand = SecureRandom.getInstance("ECDRBG","JsafeJCE");
		rand.setSeed(GeneTimeSeed());
		byte[] macMsg = new byte[1024];
		rand.nextBytes(macMsg);
		String mac_digest = Send_Receive(Base64Coder.encodeLines(macMsg));
		
		if(mac_digest.equals(Base64Coder.encodeLines(mac.doFinal(macMsg))))
			System.out.println("Alice and Bob have same Shared Secret");
		else
			System.out.println("Alice and Bob DO NOT have same Shared Secret");
		
		//generate AES key and IV
		MessageDigest hash_Alice = MessageDigest.getInstance("SHA-256");
		hash_Alice.update(sharedSecret);
		for(int i = 0; i<1000;i++){
			hash_Alice.update(hash_Alice.digest());
		}
		byte[] digest1 = hash_Alice.digest();
		
		
		hash_Alice.update(sharedSecret);
		for(int i = 0; i<50;i++){
			hash_Alice.update(hash_Alice.digest());
		}
		byte[] digest2 = hash_Alice.digest();
		
		GeneAESKeyandIV AESKeyandIV = new GeneAESKeyandIV(digest1,digest2);
		IV = AESKeyandIV.getIV();
		AESKey = AESKeyandIV.getKey();
		
		
		
		//generate KeyWrappingKey
		hash_Alice.update(sharedSecret);
		for(int i = 0; i<100;i++){
			hash_Alice.update(hash_Alice.digest());
		}
		
		byte[] digest3 = hash_Alice.digest();
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom1.setSeed(digest3);
		generator.init(256, secureRandom1);
		KeyWrapKey = generator.generateKey();
		//System.out.println("KeyWrapKey" + Base64Coder.encodeLines(KeyWrapKey.getEncoded()));
		byte[] WrapIV = new byte[16];
		System.arraycopy(digest3, 0, WrapIV, 0, 16);
		//do Key Wrapping Process
		AESandIV = AESKeyandIV.GetKeyandIV();;
		Wrap wrap = new Wrap(AESandIV,KeyWrapKey,WrapIV);
		WrappedKey = wrap.doWrap();
		//System.out.println("IV " + Base64Coder.encodeLines(WrapIV));
		//Key Confirmation for Transported Keying Material
		secureRandom1 = SecureRandom.getInstance("SHA1PRNG","JsafeJCE");
		secureRandom1.setSeed(GeneTimeSeed());
		// receive EmData_Bob
		String EphemData_Bob = Send_Receive(Base64Coder.encodeLines(WrappedKey));
		byte[] nonce_Bob = Base64Coder.decodeLines(EphemData_Bob);
		byte[] nonce_Alice = new byte[256];
		secureRandom1.nextBytes(nonce_Alice);
		//receive null
		String Null = Send_Receive(Base64Coder.encodeLines(nonce_Alice));
		//generate MacKey
		secretekey = new SecretKeySpec(WrappedKey,"HmacSHA256");
		System.out.println("Mac Key length" + secretekey.getEncoded().length);
		System.out.println("secretekey" + Base64Coder.encodeLines(secretekey.getEncoded()));
		//receive MacTag
		Null = Send_Receive(Base64Coder.encodeLines(secretekey.getEncoded()));
		mac = Mac.getInstance(secretekey.getAlgorithm());
		mac.init(secretekey);
		byte[] MacMsg = new byte[nonce_Alice.length + WrappedKey.length + nonce_Bob.length + "Alice".getBytes().length + "Bob".getBytes().length];
		System.arraycopy("Alice".getBytes(), 0, MacMsg, 0, "Alice".getBytes().length);
		System.arraycopy("Bob".getBytes(), 0, MacMsg, "Alice".getBytes().length, "Bob".getBytes().length);
		System.arraycopy(nonce_Alice, 0, MacMsg, "Alice".getBytes().length+"Bob".getBytes().length, nonce_Alice.length);
		System.arraycopy(nonce_Bob, 0, MacMsg, "Alice".getBytes().length+"Bob".getBytes().length+nonce_Alice.length, nonce_Bob.length);
		System.arraycopy(WrappedKey, 0, MacMsg, "Alice".getBytes().length+"Bob".getBytes().length+nonce_Alice.length+nonce_Bob.length, WrappedKey.length);
		
		byte[] MacTag = mac.doFinal(MacMsg);
		System.out.println("MacTag length : " + MacTag.length);
		
		if(Null.equals(Base64Coder.encodeLines(MacTag)))
			System.out.println("Key Confirmation Completed");
		else
			System.out.println("Key Confirmation Faild");
		
		//encrypt File
		EncryptFile encryptFile = new EncryptFile(AESKey,IV,getBytesFromFile(new File("plain.txt")));
		ciphertext = encryptFile.encryption();
		encryptFile.SaveCiphertoFile();
		//send ciphertext to Bob
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
		
		//generate ECDSA signature for this transmission
		KeyPair ecKeyPair = null;
		Signature ecdsaSigner = null;
		SecureRandom random = SecureRandom.getInstance("ECDRBG", "JsafeJCE");
		random.setSeed(GeneTimeSeed());
		KeyPairGenerator ecKeyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "JsafeJCE");
		ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("K571");
		ecKeyPairGenerator.initialize(ecParamSpec, random);
		ecKeyPair = ecKeyPairGenerator.genKeyPair();
		SignaturePublicKey = (ECPublicKey)ecKeyPair.getPublic();
		SignaturePrivateKey = (ECPrivateKey)ecKeyPair.getPrivate();
		
		
		ecdsaSigner = Signature.getInstance("SHA256/ECDSA");
		ecdsaSigner.initSign(SignaturePrivateKey);
		byte[] input = new byte[ciphertext.length + WrappedKey.length ];
		System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
		System.arraycopy(WrappedKey, 0, input, ciphertext.length, WrappedKey.length);
		hash_Alice.update(input);
		byte[] message = hash_Alice.digest();
		ecdsaSigner.update(message, 0, message.length);
		byte[] signature = ecdsaSigner.sign();
		
		//send SignaturePublick Key to Bob
		String response = Send_Receive(Base64Coder.encodeLines(SignaturePublicKey.getEncoded()));
		System.out.println("Bob :  " + response);
		
		
		//send Signature to Bob
		response = Send_Receive(Base64Coder.encodeLines(signature));
		System.out.println("Bob :   " + response);
		
		
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
	private static byte[] GeneTimeSeed() throws IOException{
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
