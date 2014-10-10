package com.chen;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.http.util.EncodingUtils;
import biz.source_code.base64Coder.Base64Coder;
import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
public class LAB3_ECDSA0Activity extends Activity {
	
	
	  private TextView plainTextView;
	  private boolean verify;
	  
    /** Called when the activity is first created. */
    @Override
    
    
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
   
        final Button geneKeyPairButton=(Button)findViewById(R.id.geneKeyPair);
        final Button publicKeybButton=(Button)findViewById(R.id.publicKey);
        final Button privateKeyButton=(Button)findViewById(R.id.privateKey);
        final Button creatSha256HashButton=(Button)findViewById(R.id.creatSha256Hash);
        final Button creatSignButton=(Button)findViewById(R.id.creatSigna);
        final Button verifySignButton=(Button)findViewById(R.id.verifysign);
        final Button geneRandButton=(Button)findViewById(R.id.geneRandNum);
        final Button encryptRandButton=(Button)findViewById(R.id.encrypRand);
        final Button decryptRandButton=(Button)findViewById(R.id.decrypRand);
        final Button geneKeyPairButton_ECDSA = (Button)findViewById(R.id.geneKeyPair_ECDSA);
        final Button publicKeyButton_ECDSA = (Button)findViewById(R.id.publicKey_ECDSA);
        final Button privateKeyButton_ECDSA = (Button)findViewById(R.id.privateKey_ECDSA);
        final Button createSignButton_ECDSA = (Button)findViewById(R.id.creatSigna_ECDSA);
        final Button verifySignButton_ECDSA = (Button)findViewById(R.id.verifysign_ECDSA);
        
        plainTextView=(TextView)findViewById(R.id.plaintext);
       geneKeyPairButton.setOnClickListener(new OnClickListener() {
		
		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
			generateKeyPairs();
			
			
		}
	});
    
    privateKeyButton.setOnClickListener(new OnClickListener() {
		
		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
			showResult("Kprivate.txt");
		}
	});  
    
    publicKeybButton.setOnClickListener(new OnClickListener() {
		
		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
		showResult("Kpublic.txt");	
		}
	});
    
    creatSha256HashButton.setOnClickListener(new OnClickListener() {
		
		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
	   createSha256Hash();	
	   System.out.println("success createShaHash");
	   showResult("Hash.txt");
		}
	});
    

    
    creatSignButton.setOnClickListener(new OnClickListener() {
		
		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
			createSign();
			showResult("Sig.txt");
		}
	});
    
    verifySignButton.setOnClickListener(new OnClickListener() {
		
		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
			verifySign();
			Toast.makeText(LAB3_ECDSA0Activity.this, "result of verify: "+verify,
				     Toast.LENGTH_LONG).show();
		}
	});
    

    
    geneRandButton.setOnClickListener(new OnClickListener() {
		
		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
		try {
			geneRandNum();
			showResult("Rand.txt");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		}
	});
    

    
    
    encryptRandButton.setOnClickListener(new OnClickListener() {
		
		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
			encryptRandNum();
			showResult("En-Ran.txt");
		}
	});
            
    decryptRandButton.setOnClickListener(new OnClickListener() {
		
		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
			decryptRand();
			showResult("De-Ran.txt");
		}
	});
        
        
        // create privateKey and publicKey

        geneKeyPairButton_ECDSA.setOnClickListener(new OnClickListener(){
        	
        	public void onClick(View v){
        		try {
					geneKeyPair_ECDSA();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchProviderException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidAlgorithmParameterException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
        	}
        });
        publicKeyButton_ECDSA.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View v) {
				// TODO Auto-generated method stub
				
				showResult("publicKey-ECDSA.txt");
			}
		});
        privateKeyButton_ECDSA.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View v) {
				// TODO Auto-generated method stub
				
				showResult("privateKye-ECDSA.txt");
			}
		});
        createSignButton_ECDSA.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View v) {
				// TODO Auto-generated method stub
				
					
					try {
						createSign_ECDSA();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					showResult("Sign-ECDSA.txt");
				
			}
		});
        verifySignButton_ECDSA.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View v) {
				// TODO Auto-generated method stub
				try {
					VerifySign_ECDSA();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Toast.makeText(LAB3_ECDSA0Activity.this, "result of verify: "+verify,
					     Toast.LENGTH_LONG).show();
			}
		});
        
        
        
        
    }
      
    public void showResult(String fileName){
		
    	 String res=""; 
         
         try{ 
          FileInputStream fin = openFileInput(fileName); 
          int length = fin.available(); 
          byte [] buffer = new byte[length]; 
          fin.read(buffer);     
          res = EncodingUtils.getString(buffer, "UTF-8"); 
          fin.close();     
         } 
         catch(Exception e){ 
          e.printStackTrace(); 
         } 
         
         plainTextView.setText(res);
     }
     public void geneKeyPair_ECDSA() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException

     { 	
    	 //register provider of SC
    	 Provider jsafeProvider = new org.spongycastle.jce.provider.BouncyCastleProvider();
    	 Security.insertProviderAt (jsafeProvider, 1);
    	
    	
    	//generate Ecparameter
    	 ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp224k1");
    	 KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "SC");
    	 kpg.initialize(ecParamSpec);
    	 KeyPair kpA = kpg.generateKeyPair();
    	 ECPublicKey pub_s = (ECPublicKey)kpA.getPublic();
    	 ECPrivateKey priv_s = (ECPrivateKey)kpA.getPrivate();
    	 
    	 byte[] pub = pub_s.getEncoded();
    	 byte[] priv = priv_s.getEncoded();
    	 
    	 String Base64Key = Base64Coder.encodeLines(priv);

    	 FileOutputStream fos1 =openFileOutput("privateKye-ECDSA.txt", MODE_PRIVATE); 		
    	 fos1.write(Base64Key.getBytes());

			
    	 Base64Key = Base64Coder.encodeLines(pub);
    	 fos1 = openFileOutput("publicKey-ECDSA.txt", MODE_PRIVATE);
    	 fos1.write(Base64Key.getBytes());

    	 fos1.close();

    	 
     }
    	
     
 	private static PrivateKey getPrivateKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
 	{
 		byte[] encodedKey = readBase64File(fileName);
 		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encodedKey);
 		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
 		PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);
 		return privKey;
 	}
     
	public void createSign_ECDSA() throws Exception
     {	
		Provider jsafeProvider = new org.spongycastle.jce.provider.BouncyCastleProvider();
   	    Security.insertProviderAt (jsafeProvider, 1);
   	    // read in private key
    	FileInputStream f1s = openFileInput("privateKye-ECDSA.txt");
    	int length = f1s.available();
    	byte[] buffer = new byte[length];
    	f1s.read(buffer);
    	f1s.close();
    	String privateKeyString = new String(buffer);
    	byte[] privateKeyBytes = Base64Coder.decodeLines(privateKeyString);
    	PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    	KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
    	ECPrivateKey privKey = (ECPrivateKey)keyFactory.generatePrivate(privKeySpec);
 		
 		
 		
 		
 		
 		
 		

 		// read in hash
 		FileInputStream f2s = openFileInput("Hash.txt");
 		
 		
 		int length2 = f2s.available();
 		byte[] buffer1 = new byte[length2];
 		f2s.read(buffer1);
 		String shash = new String(buffer1);
 		f2s.close();
 		byte[] bhash = Base64Coder.decode(shash);
 		byte[] message = bhash;
 		//showResult("Hash.txt");
 		
 		//ecDSA256 ss = new ecDSA256();
 		//SecureRandom random = new SecureRandom();
 		
 		//ss.engineInitSign(privKey, random);
 		// Get an EC private key for signing
 		Signature ecdsaSigner = null;
 		try
 		{
 			
 			ecdsaSigner = Signature.getInstance("SHA256withECDSA","SC");
 			ecdsaSigner.initSign(privKey);
 			ecdsaSigner.update(message, 0, message.length);
 			 
 			// Now that all of the message data has been passed in,
 			// sign() will perform a ECDSA sign operation on the message
 			// and output the signature.
 			byte[] signature = ecdsaSigner.sign();
 			String encodedString = Base64Coder.encodeLines(signature,0,signature.length,76,"");
 			FileOutputStream output = openFileOutput("Sign-ECDSA.txt",MODE_PRIVATE);
 			output.write(encodedString.getBytes());
 			output.close();
 			
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
     public void VerifySign_ECDSA() throws Exception
     {
    		try
    		{

    		//read in publickey 
    		FileInputStream f1s = openFileInput("publicKey-ECDSA.txt");
    		int length = f1s.available();
    		byte []  buffer = new byte[length];
    		f1s.read(buffer);
    		f1s.close();
    		String publicKeyString = new String(buffer);
    		byte[] publicKeyByte = Base64Coder.decodeLines(publicKeyString);
    		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
    		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyByte);
    		
    		//read in signature
    		FileInputStream f2s = openFileInput("Sign-ECDSA.txt");
    		int length2 = f2s.available();
    		byte[] buffer2 = new byte[length2];
    		f2s.read(buffer2);
    		f2s.close();
    		String sigToVerifyString = new String(buffer2);
    		byte[] sigToVerify = Base64Coder.decodeLines(sigToVerifyString);
    		//read in hash
    		FileInputStream f3s = openFileInput("Hash.txt");
    		int length3 = f3s.available();
    		byte[] buffer3 = new byte[length3];
    		f3s.read(buffer3);
    		f3s.close();
    		String shash = new String(buffer3);
    		byte[] bhash = Base64Coder.decodeLines(shash);
    		

    		// The verification object.
    		Signature ecdsaVerifier = null;
    		
    		// Verify the signature.

    		// Get an EC private key for signing
    		ECPublicKey publicKey = (ECPublicKey)keyFactory.generatePublic(publicKeySpec);
    		
    		// This is the message to sign.
    		byte[] message = bhash;
    		
    		
    		byte [] signature = sigToVerify;
    		
    		
    		ecdsaVerifier = Signature.getInstance("SHA256withECDSA", "SC");

    		
    		ecdsaVerifier.initVerify(publicKey);

    		// Pass in the message to be verified.
    		ecdsaVerifier.update(message, 0, message.length);

    		
    		boolean verified = ecdsaVerifier.verify(signature);
    		ecdsaVerifier.initVerify(publicKey);
    		ecdsaVerifier.update(message, 0, message.length);
    		verify = ecdsaVerifier.verify(signature);
    		System.out.println("verify : " + verify);
    		System.out.println("verified : " + verified);

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
		
     public void generateKeyPairs(){
    	 try {
 			
 			System.out.println("**********************");

 			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
 			keyGen.initialize(2048);
 			KeyPair keypair = keyGen.genKeyPair();
 			PrivateKey privateKey = keypair.getPrivate();
 			PublicKey publicKey = keypair.getPublic();

 			byte[] priv = privateKey.getEncoded();
 		
 			byte[] pub = publicKey.getEncoded();
 			
 			String Base64Key = Base64Coder.encodeLines(priv, 0, priv.length, 76, "");
 			//FileOutputStream fos1 =openFileOutput("Kprivate.txt", MODE_PRIVATE);
 			FileOutputStream fos1 =openFileOutput("Kprivate.txt", MODE_PRIVATE); 		
 			fos1.write(Base64Key.getBytes());

 			Base64Key = Base64Coder.encodeLines(pub, 0, pub.length, 76, "");
 			fos1 = openFileOutput("Kpublic.txt", MODE_PRIVATE);
 			fos1.write(Base64Key.getBytes());

 			fos1.close();
 		} catch (IOException e) {
 		} catch (java.security.NoSuchAlgorithmException e) {
 			System.out.println("No Such Algorithm");
 		}
 		
 	}
     public void createSha256Hash(){
    	 try {
            System.out.println("A");
 			MessageDigest hash = MessageDigest.getInstance("SHA-256");
 			
 			FileInputStream f1s=openFileInput("plaintext.txt");
 			
 			int length = f1s.available(); 
 	        byte [] buffer = new byte[length]; 
 	        f1s.read(buffer);      
 	        f1s.close();     

 			hash.update(buffer);
 			byte[] digest = hash.digest();
 		// convert the digest into a string
 			String encodedString = Base64Coder.encodeLines(digest, 0, digest.length, 76, "");
            FileOutputStream fos=openFileOutput("Hash.txt", MODE_PRIVATE);
 			fos.write(encodedString.getBytes());
 			fos.close();

 		}catch (java.security.NoSuchAlgorithmException e) {
 		}catch (IOException e){
 			
 		}

 	}
     
     public void createSign(){
    	 try {
    		FileInputStream f1s=openFileInput("Kprivate.txt");
  			
  			int length = f1s.available(); 
  	        byte [] buffer = new byte[length]; 
  	        f1s.read(buffer);      
  	        f1s.close();   
 			String privateKeyString = new String(buffer);
 			byte[] privateKeyBytes = Base64Coder.decode(privateKeyString);
 			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
 			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
 			PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

 			Signature dsa = Signature.getInstance("SHA256withRSA");
 			dsa.initSign(privateKey2);
// 			String shash = getStringFromFile("Hash.txt");
// 			byte[] bhash = Base64Coder.decode(shash);
 			FileInputStream f2s=openFileInput("Hash.txt");
 			int length2=f2s.available();
 			byte []buffer1=new byte[length2];
 			f2s.read(buffer1);
 			String shash=new String(buffer1);
            f2s.close();
            byte[]bhash=Base64Coder.decode(shash);
 			dsa.update(bhash);
 			byte[] realSig = dsa.sign();

 			String encodedString = Base64Coder.encodeLines(realSig, 0, realSig.length, 76, "");
 			FileOutputStream output = openFileOutput("Sig.txt",MODE_PRIVATE);
 			output.write(encodedString.getBytes());
 			output.close();

 		} catch (IOException e) {
 		}

 		catch (java.security.spec.InvalidKeySpecException e) {
 			System.out.println("Invalid Key Spec Exception");
 		} catch (java.security.SignatureException e) {
 			System.out.println("Signature Exception");
 		} catch (java.security.InvalidKeyException e) {
 			System.out.println("Invalid Key");
 		} catch (java.security.NoSuchAlgorithmException e) {
 			System.out.println("No Such Algorithm");
 		}
     }
     
     public void verifySign(){
    	 try {
    		
    		FileInputStream f1s=openFileInput("Kpublic.txt");
   			int length = f1s.available(); 
   	        byte [] buffer = new byte[length]; 
   	        f1s.read(buffer);      
   	        f1s.close();   
  			String publicKeyString = new String(buffer);
 			byte[] publicKeyByte = Base64Coder.decode(publicKeyString);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
 			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyByte);
 			PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
 			
            FileInputStream f2s=openFileInput("Sig.txt");
  			int length2 = f2s.available(); 
  	        byte [] buffer2 = new byte[length2]; 
  	        f2s.read(buffer2);      
  	        f2s.close();   
 			String sigToVerifyString = new String(buffer2);
            byte[] sigToVerify = Base64Coder.decode(sigToVerifyString);
            Signature sig = Signature.getInstance("SHA256withRSA");
 			sig.initVerify(pubKey);
 			
            FileInputStream f3s=openFileInput("Hash.txt");
  			int length3 = f3s.available(); 
  	        byte [] buffer3 = new byte[length3]; 
  	        f3s.read(buffer3);      
  	        f3s.close();   
 			String shash = new String(buffer3);
            byte[] bhash = Base64Coder.decode(shash);
            sig.update(bhash);

 			verify = sig.verify(sigToVerify);
 			System.out.println("signature verifies: " + verify);

 		} catch (java.security.spec.InvalidKeySpecException e) {
 			System.out.println("Invalid Key Spec Exception");
 		} catch (java.security.SignatureException e) {
 			System.out.println("Signature Exception");
 		} catch (java.security.InvalidKeyException e) {
 			System.out.println("Invalid Key");
 		} catch (java.security.NoSuchAlgorithmException e) {
 			System.out.println("No Such Algorithm");
 		} catch (IOException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		}
     }
     
     public void geneRandNum() throws IOException, NoSuchAlgorithmException{
    		// Create a secure random number generator
 		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
 		// Get 1024 random bits
 		byte[] bytes = new byte[1024 / 8];
 		sr.nextBytes(bytes);

 		// save the random number in base64 format
 		String encodedString = Base64Coder.encodeLines(bytes, 0, bytes.length, 76, "");
 		FileOutputStream output = openFileOutput("Rand.txt",MODE_PRIVATE);
 		output.write(encodedString.getBytes());
 		output.close();
     }
     
     public void encryptRandNum(){
    	 try{
    		 FileInputStream f1s=openFileInput("Kpublic.txt");
    			int length = f1s.available(); 
    	        byte [] buffer = new byte[length]; 
    	        f1s.read(buffer);      
    	        f1s.close();   
   			String publicKeyString = new String(buffer); 
    		 
 		//	String publicKeyString = getStringFromFile("Kpublic.txt");
 			byte[] publicKeyByte = Base64Coder.decode(publicKeyString);

 			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
 			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyByte);
 			PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);

 			FileInputStream f2s=openFileInput("Rand.txt");
   			int length2 = f2s.available(); 
   	        byte [] buffer2 = new byte[length2]; 
   	        f2s.read(buffer2);      
   	        f2s.close();   
  			String randString = new String(buffer2);
 			//String randString = getStringFromFile("RAND.txt");
 			byte[] rand = Base64Coder.decode(randString);

 			Cipher cipher = Cipher.getInstance("RSA");
 			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
 			byte[] cipherData = cipher.doFinal(rand);

 			String encodedString = Base64Coder.encodeLines(cipherData, 0, cipherData.length, 76, "");
 			FileOutputStream output = openFileOutput("En-Ran.txt",MODE_PRIVATE);
 			output.write(encodedString.getBytes());
 			output.close();


 		} catch(java.security.spec.InvalidKeySpecException e){
 			
 		} catch (NoSuchAlgorithmException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		} catch (NoSuchPaddingException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		} catch (IOException e) {
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
     
     
     public void decryptRand(){
    	 try {
    		FileInputStream f1s=openFileInput("Kprivate.txt");
 			int length = f1s.available(); 
 	        byte [] buffer = new byte[length]; 
 	        f1s.read(buffer);      
 	        f1s.close();   
			String privateKeyString = new String(buffer);
 			//String privateKeyString = getStringFromFile("Kprivate.txt");
 			byte[] privateKeyBytes = Base64Coder.decode(privateKeyString);

 			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
 			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
 			PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

 			FileInputStream f2s=openFileInput("En-Ran.txt");
 			int length2 = f2s.available(); 
 	        byte [] buffer2 = new byte[length2]; 
 	        f2s.read(buffer2);      
 	        f2s.close();   
			String eRandString = new String(buffer2);
 			//String eRandString = getStringFromFile("En-RAN.txt");
 			byte[] eRand = Base64Coder.decode(eRandString);

 			Cipher cipher = Cipher.getInstance("RSA");
 			cipher.init(Cipher.DECRYPT_MODE, privateKey2);
 			byte[] cipherData = cipher.doFinal(eRand);

 			FileOutputStream output = openFileOutput("De-Ran.txt",MODE_PRIVATE);
 			String decodedString = Base64Coder.encodeLines(cipherData, 0, cipherData.length, 76, "");
 			output.write(decodedString.getBytes());
 			output.close();

 		} catch (java.security.spec.InvalidKeySpecException e) {
 			System.out.println("Invalid Key Spec");
 		} catch (java.security.InvalidKeyException e) {
 			System.out.println("Invalid Key");
 		} catch (java.security.NoSuchAlgorithmException e) {
 			System.out.println("No Such Algorithm");
 		} catch (javax.crypto.NoSuchPaddingException e) {
 			System.out.println("No Such Padding");
 		} catch (javax.crypto.IllegalBlockSizeException e) {
 			System.out.println("Illegal Block Size");
 		} catch (javax.crypto.BadPaddingException e) {
 			System.out.println("Bad Padding");
 		} catch (IOException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		}
     }

 	private static void writeByteToBase64File(String filepath, byte[] data) throws IOException
 	{
 		FileOutputStream fos = new FileOutputStream(new File(filepath));
 		fos.write(byteToBase64(data).getBytes());
 		fos.close();
 	}
	private static String byteToBase64( byte[] data )
	{
		return Base64Coder.encodeLines(data);
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



 	
     
     	
	
}