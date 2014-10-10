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
public class ECDSASign
{

	public static void main(String[] args) throws Exception
	{
		Provider jsafeProvider = new com.rsa.jsafe.provider.JsafeJCE();
		// Add the Crypto-J JCE Provider to the current
		// list of providers available on the system.
		Security.insertProviderAt (jsafeProvider, 1);
		
		String privfile = "ECKprivate.txt";
		String hashfile = "Hash.txt";
		String outfile = "ECSig.txt";
		// The object used to create the signature.
		Signature ecdsaSigner = null;

		// This is the message to sign.
		byte[] message = readBase64File(hashfile);
		System.out.println("File to be signed read from "+hashfile);

		// Get an EC private key for signing
		ECPrivateKey privateKey = (ECPrivateKey)getPrivateKey(privfile);
		System.out.println("Private key obtained from "+privfile);
		try
		{
			// Sign the message.

			// Get a Signature object for doing the signing using ECDSA.
			// This sample uses SHA256 for the internal message digest.
			// Other message digests that can be used with ECDSA are:
			//    SHA1, SHA224, SHA384 and SHA512.
			ecdsaSigner = Signature.getInstance("SHA256/ECDSA");

			// Initialize the signature object.
			// This call will set up signer to perform signatures using ECDSA.
			ecdsaSigner.initSign(privateKey);

			// Now, pass in the data to be signed.
			// The call to update() will process the data passed in.
			// Nothing will be output until the call to sign().
			ecdsaSigner.update(message, 0, message.length);

			// Now that all of the message data has been passed in,
			// sign() will perform a ECDSA sign operation on the message
			// and output the signature.
			byte[] signature = ecdsaSigner.sign();
			System.out.println("Signature:\n" + byteToBase64(signature));
			writeByteToBase64File(outfile, signature);
			System.out.println("Signature saved in "+outfile);
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