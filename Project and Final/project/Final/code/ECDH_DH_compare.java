package compare;

import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;



public class ECDH_DH_compare {

	public static void main(String[] args) throws NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException{
		String[] curve = {"P192","P224","P256","P384","P521","B163","B283","B409","B571","K163","K233","K283",
    			"K409","K571"};
		ECGenParameterSpec agreedParameters = new ECGenParameterSpec("K571");
		
		geneKeyPairECDH AliceGeneKeyPair = new geneKeyPairECDH(agreedParameters);
		
		PrivateKey ECDHPrivateKey_Alice = AliceGeneKeyPair.getPrivateKey();
		PublicKey ECDHPublicKey_Alice  = AliceGeneKeyPair.getPublicKey();
		
		geneKeyPairECDH BobGeneKeyPair = new geneKeyPairECDH(agreedParameters);
		
		PrivateKey ECDHPrivateKey_Bob = BobGeneKeyPair.getPrivateKey();
		PublicKey ECDHPublicKey_Bob   = BobGeneKeyPair.getPublicKey();
		System.out.println("length " + ECDHPublicKey_Bob.getEncoded().length);
		KeyAgreement ECkeyAgree_Alice = KeyAgreement.getInstance("ECDH", "JsafeJCE");
		ECkeyAgree_Alice.init(ECDHPrivateKey_Bob, agreedParameters);
		KeyAgreement ECkeyAgree_Bob = KeyAgreement.getInstance("ECDH", "JsafeJCE");
		ECkeyAgree_Bob.init(ECDHPrivateKey_Alice, agreedParameters);
		int b = 0;
		long start=0,end=0,average=0;
		for(int j=0;j<curve.length;j++){
			agreedParameters = new ECGenParameterSpec(curve[j]);
			AliceGeneKeyPair = new geneKeyPairECDH(agreedParameters);
			ECDHPrivateKey_Alice = AliceGeneKeyPair.getPrivateKey();
			BobGeneKeyPair = new geneKeyPairECDH(agreedParameters);
			ECDHPublicKey_Bob   = BobGeneKeyPair.getPublicKey();
			ECkeyAgree_Alice = KeyAgreement.getInstance("ECDH", "JsafeJCE");
			ECkeyAgree_Alice.init(ECDHPrivateKey_Alice, agreedParameters);
			average = 0;
			for(int i=0;i<1000;i++){
				
				start = System.nanoTime();
				ECkeyAgree_Alice.doPhase(ECDHPublicKey_Bob, true);
				byte[] sharedSecret = ECkeyAgree_Alice.generateSecret();
				end = System.nanoTime();
				average = average + (end - start);
				 b = sharedSecret.length;
			}
			System.out.println("LENGTH : " + b);
			System.out.println("Curve : " + curve[j] + "  ECDH average Time : "  + average/1000);
		}
		
		AlgorithmParameterGenerator paramGen =
				 AlgorithmParameterGenerator.getInstance("DH");
				 paramGen.init(1024);
				 AlgorithmParameters params = paramGen.generateParameters();
				 DHParameterSpec dhSpec =
				 (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
		geneKeyPairDH AliceGeneKeyPair_DH = new geneKeyPairDH(dhSpec);
		
		PrivateKey DHPrivateKey_Alice = AliceGeneKeyPair_DH.getPrivateKey();
		PublicKey DHPublicKey_Alice  = AliceGeneKeyPair_DH.getPublicKey();
		
		geneKeyPairDH BobGeneKeyPair_DH = new geneKeyPairDH(dhSpec);
		
		PrivateKey DHPrivateKey_Bob = BobGeneKeyPair_DH.getPrivateKey();
		PublicKey DHPublicKey_Bob   = BobGeneKeyPair_DH.getPublicKey();
		System.out.println("LENGTH  :  " + DHPublicKey_Bob.getEncoded().length);
		KeyAgreement DHkeyAgree_Alice = KeyAgreement.getInstance("DH");
		DHkeyAgree_Alice.init(DHPrivateKey_Alice);
		KeyAgreement DHkeyAgree_Bob = KeyAgreement.getInstance("DH");
		DHkeyAgree_Bob.init(DHPrivateKey_Bob);
		
		
		
		
		int a=0;
		average = 0;
		for(int i=0;i<1000;i++){
			start = System.nanoTime();
			DHkeyAgree_Alice.doPhase(DHPublicKey_Bob, true);
			byte[] sharedSecret = DHkeyAgree_Alice.generateSecret();
			
			end = System.nanoTime();
			average = average + (end - start);
			a = sharedSecret.length;
		}
		System.out.println("Length : " + a);
		System.out.println("DH average Time   : " + average/1000);
		
		
		
	}
}
