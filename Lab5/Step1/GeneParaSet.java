import java.io.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;
import java.security.spec.*;

public class GeneParaSet {
  public static void main(String[] args) {
    System.out.println("P = prime modulus");
    System.out.println("G = generator");
    System.out.println("L = bit size of random exponent");
    System.out.println("\t\tP\tG\tL");
	System.out.println("For 512 bits:\t" + genDhParams(512));
    System.out.println("For 1024 bits:\t" + genDhParams(1024));
    System.out.println("For 2048 bits:\t" + genDhParams(2048));
    System.out.println("For 4096 bits:\t" + genDhParams(4096));
    
  }
  //from http://exampledepot.com/egs/javax.crypto/GenDhParams.html
      // Returns a tab-separated string of 3 values.
    // The first number is the prime modulus P.
    // The second number is the base generator G.
    // The third number is bit size of the random exponent L.
    public static String genDhParams(int keySize) {
        try {
            // Create the parameter generator for a 1024-bit DH key pair
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(keySize);
    
            // Generate the parameters
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec
                = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
    
            // Return the three values in a string
            return dhSpec.getP()+ "\t" +dhSpec.getG()+"\t"+dhSpec.getL();
        } catch (NoSuchAlgorithmException e) {
        } catch (InvalidParameterSpecException e) {
        }
        return null;
    }

}
