import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class test1 {
	public static void main(String[] args)
	{	
		try{
		 String initKey = "2011BCSChampion-AuburnUniversity";
		 KeyGenerator generator1 = KeyGenerator.getInstance("AES");
		 KeyGenerator generator2 = KeyGenerator.getInstance("AES");
		 SecureRandom secureRandom_Windows_PRNG = SecureRandom.getInstance("Windows-PRNG","SunMSCAPI");
		 SecureRandom secureRandom_SHA1PRNG = SecureRandom.getInstance("SHA1PRNG","SUN");
		 //SecureRandom secureRandom =  new SecureRandom(initKey.getBytes());
		 secureRandom_SHA1PRNG.setSeed(initKey.getBytes());
		 secureRandom_Windows_PRNG.setSeed(initKey.getBytes());
		 
		 System.out.println("random number of SHA1PRNG");
		 // long starttime = System.nanoTime();
		 System.out.println("random :" + secureRandom_SHA1PRNG.nextInt());
		 System.out.println("random :" +secureRandom_SHA1PRNG.nextInt());
		 
		 //long estimatetime = System.nanoTime() - starttime;
		 // System.out.println("time for generate 2 SHA1PRNG random number" + estimatetime);
		 System.out.println("random number of Windows-PRNG");
		 //starttime = System.nanoTime();
		 System.out.println("random :" + secureRandom_Windows_PRNG.nextInt());
		 System.out.println("random :" + secureRandom_Windows_PRNG.nextInt());
		 // estimatetime = System.nanoTime() - starttime;
		 //System.out.println("time for generate 2 Windows-PRNG random number" + estimatetime);
		 //initial SecureRandom again with SHA1PRNG using same seed again
		 System.out.println("set SecureRandom again and generate Randum number again");
		 secureRandom_Windows_PRNG = SecureRandom.getInstance("Windows-PRNG","SunMSCAPI");
		 secureRandom_SHA1PRNG = SecureRandom.getInstance("SHA1PRNG","SUN");
		 secureRandom_SHA1PRNG.setSeed(initKey.getBytes());
		 secureRandom_Windows_PRNG.setSeed(initKey.getBytes());
		 
		 System.out.println("generate random number again");
		 System.out.println("random number of SHA1PRNG");
		 System.out.println("random :" + secureRandom_SHA1PRNG.nextInt());
		 System.out.println("random :" + secureRandom_SHA1PRNG.nextInt());
		 System.out.println("random number of Windows-PRNG");
		 System.out.println("random :" + secureRandom_Windows_PRNG.nextInt());
		 System.out.println("random :" + secureRandom_Windows_PRNG.nextInt());
		 
	     generator1.init(256,secureRandom_SHA1PRNG);
	     generator2.init(256, secureRandom_Windows_PRNG);
	   /*  for(int n =0; n<Security.getProviders().length;n++)
	     {
	    	 System.out.println("Provider List :" + Security.getProviders()[n].getName());
	    	 System.out.println("Provider Service List :" + Security.getProviders()[n].getServices());
	     }*/
	    // starttime = System.nanoTime();
	     SecretKey Key1 = generator1.generateKey();
	     SecretKey Key2 = generator1.generateKey();
	     //estimatetime = System.nanoTime() - starttime;
	     //System.out.println("time one : " + estimatetime);
	     System.out.println("KEY of SHA1PRNG");
	     System.out.println("Using Key1: ");
	     for (byte b : Key1.getEncoded()) {
	         System.out.format("%02x", b);
	         }
	     System.out.println();
	     System.out.println("Using Key2: ");
	     for (byte b : Key2.getEncoded()) {
	         System.out.format("%02x", b);
	         }
	     System.out.println();
	     System.out.println("KEY of Windows_PRNG");
	     //starttime = System.nanoTime();
	     Key1 = generator2.generateKey();
	     Key2 = generator2.generateKey();
	     //estimatetime = System.nanoTime() - starttime;
	     //System.out.println("time two : " + estimatetime);
	     System.out.println("Using Key1: ");
	     for (byte b : Key1.getEncoded()) {
	         System.out.format("%02x", b);
	         }
	     System.out.println();
	     System.out.println("Using Key2: ");
	     for (byte b : Key2.getEncoded()) {
	         System.out.format("%02x", b);
	         }
		}catch(Exception e)
        {
	          System.out.println(e.getMessage());
	          
	        }
	}
}
