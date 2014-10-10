/* ECDSA.java
* Copyright (c) 1997-2009, RSA Security Inc.
*
* This file is used to demonstrate how to interface to an RSA
* Security licensed development product.  You have a
* royalty-free right to use, modify, reproduce and distribute this
* demonstration file (including any modified version), provided that
* you agree that RSA Security has no warranty, implied or
* otherwise, or liability for this demonstration file or any modified
* version.
*
*/
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;


/*
* This application demonstrates the use of RSA Security's JCE provider to
* create and verify digital signatures using the EC Digital Signature Algorithm
* (ECDSA).
* <p>
* This sample uses a pre-generated key pair for signing and verifying.
* For sample code to generate a new key pair, see ECKeyGen.
*/
public class ECDSAVerify
{

	public static void main(String[] args) throws Exception
	{
		try
		{
		Provider jsafeProvider = new com.rsa.jsafe.provider.JsafeJCE();
		// Add the Crypto-J JCE Provider to the current
		// list of providers available on the system.
		Security.insertProviderAt (jsafeProvider, 1);
		
		String pubfile = "ECKpublic.txt";
		String hashfile = "Hash.txt";
		String sigfile = "ECSig.txt";

		// The verification object.
		Signature ecdsaVerifier = null;
		
		// Verify the signature.

		// Get an EC private key for signing
		ECPublicKey publicKey = (ECPublicKey)getPublicKey(pubfile);
		System.out.println("Public key obtained from "+pubfile);
		
		// This is the message to sign.
		byte[] message = readBase64File(hashfile);
		System.out.println("File to be verified read from "+hashfile);
		
		byte [] signature = readBase64File(sigfile);
		System.out.println("Signature to be verified read from "+sigfile);
		// Get a signature object for ECDSA signature verification using
		// SHA256 for the message digest algorithm.
		ecdsaVerifier = Signature.getInstance("SHA256/ECDSA", "JsafeJCE");

		// Initialize the verify object.  This call will set up
		// dsaVerifier to perform signature verification using ECDSA.
		ecdsaVerifier.initVerify(publicKey);

		// Pass in the message to be verified.
		ecdsaVerifier.update(message, 0, message.length);

		// Now that all of the message data has been passed in from calls to
		// update(), pass the signature into the verify() method.
		// If the signature is valid for the given message, it will output
		// true, otherwise it will output false.
		boolean verified = ecdsaVerifier.verify(signature);

		if (!verified)
		{
			System.out.println("Verification failed!");
			System.exit(1);
		}
		System.out.println("Signature Verified!!");
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
			System.exit(1);
		}
		catch (IOException e)
		{
			e.printStackTrace();
			System.exit(1);
		}
	}
	
	
	private static PublicKey getPublicKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		byte[] encodedKey = readBase64File(fileName);
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		return pubKey;
	}
	
	private static PrivateKey getPrivateKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		byte[] encodedKey = readBase64File(fileName);
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
		PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);
		return privKey;
	}
	
	
	
		//The following are service methods for file IO and data formating (base64 to binary)
	
	
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


	/**
	* Method takes in a byte array and returns the base64 encoded String
	*
	* @param data	byte array containing the binary input
	*
	* @return String containing the base64 encoded data
	*/
	private static String byteToBase64( byte[] data )
	{
		return Base64Coder.encodeLines(data);
	}

	/**
	* Method takes in base 64 string and returns the raw byte[]
	*
	* @param data	string input
	*
	* @return raw byte[]
	*/
	private static byte[] base64ToBytes( String data )
	{
		return Base64Coder.decodeLines(data);
	}

	private static byte[] readBase64File(String filepath) throws IOException
	{
		byte[] encoded = getBytesFromFile(new File(filepath));
		String base64 = new String(encoded);
		return base64ToBytes(base64);
	}

	private static void writeByteToBase64File(String filepath, byte[] data) throws IOException
	{
		FileOutputStream fos = new FileOutputStream(new File(filepath));
		fos.write(byteToBase64(data).getBytes());
		fos.close();
	}
}