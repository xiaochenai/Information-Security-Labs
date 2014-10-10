import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.security.Security; 
import org.bouncycastle.jce.provider.BouncyCastleProvider; 


public class ECDSAKeyGen
{
	public static void main(String[] args)
	{
		Provider jsafeProvider = new com.rsa.jsafe.provider.JsafeJCE();
		// Add the Crypto-J JCE Provider to the current
		// list of providers available on the system.
		Security.insertProviderAt (jsafeProvider, 1);

		try
		{
			String pubfile = "ECKpublic.txt";
			String privfile = "ECKprivate.txt";
			
			// The key pair objects.
			KeyPair ecKeyPair = null;

			// A random number generator will be used to generate
			// the EC key pair.
			SecureRandom random = SecureRandom.getInstance("ECDRBG", "JsafeJCE");

			// Seeding is the most important aspect of dealing with a secure
			// random number generator. It is extremely important that you seed
			// the PRNG with a value that contains sufficient entropy.
			// The following example uses a seed generator.

			// Get an instance of an EC key pair generator.
			KeyPairGenerator ecKeyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "JsafeJCE");

			// We want to create the EC key pair for the B571 curve.
			ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("B571");

			// Initialize the key pair generator.
			ecKeyPairGenerator.initialize(ecParamSpec, random);

			// Generate the EC key pair.
			ecKeyPair = ecKeyPairGenerator.genKeyPair();
			ECPublicKey pub = (ECPublicKey)ecKeyPair.getPublic();
			ECPrivateKey priv = (ECPrivateKey)ecKeyPair.getPrivate();
				

			writeByteToBase64File(pubfile, pub.getEncoded());
			writeByteToBase64File(privfile, priv.getEncoded());
			System.out.println("ECDSA keys generated and saved in "+pubfile+" and "+privfile);
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
			System.exit(1);
		}
		catch (NoSuchProviderException e)
		{
			e.printStackTrace();
			System.exit(1);
		}
		catch (InvalidAlgorithmParameterException e)
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

	private static void writeByteToBase64File(String filepath, byte[] data) throws IOException
	{
		FileOutputStream fos = new FileOutputStream(new File(filepath));
		fos.write(byteToBase64(data).getBytes());
		fos.close();
	}

}
