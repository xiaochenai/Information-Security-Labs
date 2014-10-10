package compare;
//compare the speed for ECDSA and RSA to Sign same file's signature
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

public class ECDSA_RSADSA {
	public static void main(String[] args){
		try{
			//generate ECDSA Key Pair
			KeyPair ecKeyPair = null;
			SecureRandom random = SecureRandom.getInstance("ECDRBG", "JsafeJCE");
			String[] curve = {"P192","P224","P256","P384","P521","B163","B233","B283","B409","B571"};
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] Digest = new byte[256];
			long average=0,start=0,end=0;
			//sign plain.txt directly
			byte[] message = getBytesFromFile(new File("plain.txt"));
			byte[] signature;
			for(int j = 0;j<curve.length;j++){
			KeyPairGenerator ecKeyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "JsafeJCE");
			ECGenParameterSpec ecParamSpec = new ECGenParameterSpec(curve[j]);
			System.out.println("CURVE :  " + curve[j]);
			ecKeyPairGenerator.initialize(ecParamSpec, random);
			ecKeyPair = ecKeyPairGenerator.genKeyPair();
			ECPublicKey pub = (ECPublicKey)ecKeyPair.getPublic();
			ECPrivateKey priv = (ECPrivateKey)ecKeyPair.getPrivate();
			System.out.println("ECPriv length" + priv.getEncoded().length);
			Signature ecdsaSigner = null;
			ecdsaSigner = Signature.getInstance("SHA256/ECDSA");
			
			for(int i=0;i<1000;i++){
				ecdsaSigner.initSign(priv);
				ecdsaSigner.update(message, 0, message.length);
				start = System.nanoTime();
				signature = ecdsaSigner.sign();
				end = System.nanoTime();
				average  = (end -start) + average;
				
			}
			System.out.println("Sign Directly Time     :" + (average/1000));
			average=0;
			
			digest.update(message);
			Digest = digest.digest();
			for(int i =0;i<1000;i++){
				ecdsaSigner.initSign(priv);
				ecdsaSigner.update(Digest, 0, Digest.length);
				start = System.nanoTime();
				signature = ecdsaSigner.sign();
				end = System.nanoTime();
				average = average + (end-start);
			}
			
			System.out.println("Sign Digest Time       :" + (average/1000));
			}
			Integer[] size = {1024,2240,3072,7680,15360};
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			
			for(int j=0;j<size.length;j++){
				keyGen.initialize(size[j]);
			System.out.println("Size :  " + size[j]);
			KeyPair keypair = keyGen.genKeyPair();
			PrivateKey privateKey = keypair.getPrivate();
			PublicKey publicKey = keypair.getPublic();
			System.out.println("RSA Priv Length" + privateKey.getEncoded().length);
			//message =  getBytesFromFile(new File("plain.txt"));
			average = 0;
			Signature dsa = Signature.getInstance("SHA256withRSA");
			for(int i=0; i<1000;i++){
				
				dsa.initSign(privateKey);
				dsa.update(message,0,message.length);
				start = System.nanoTime();
				signature= dsa.sign();
				end = System.nanoTime();
				average = average + (end - start);
			}
			System.out.println("RSA Sign Directly Time :" + average/1000);
		
			average = 0;
			for(int i=0;i<1000;i++){
				
				dsa.initSign(privateKey);
				dsa.update(Digest,0,Digest.length);
				start = System.nanoTime();
				signature= dsa.sign();
				end = System.nanoTime();
				average = average + (end - start);
			}
			System.out.println("RSA Sign Digest Time   :" + average/1000);
			}
		}catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
