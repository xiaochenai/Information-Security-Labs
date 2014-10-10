import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;



//the comparison of different algorithm for SecureRandom
//generate different amount of random number
public class test2 {
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException{
		KeyGenerator Key1 = KeyGenerator.getInstance("AES");
		KeyGenerator Key2 = KeyGenerator.getInstance("AES");
		KeyGenerator Key3 = KeyGenerator.getInstance("AES");
		KeyGenerator Key4 = KeyGenerator.getInstance("AES");
		
		SecureRandom secureRandom1 = SecureRandom.getInstance("Windows-PRNG","SunMSCAPI");
		SecureRandom secureRandom2 = SecureRandom.getInstance("SHA1PRNG","SUN");
		SecureRandom secureRandom3 = SecureRandom.getInstance("ECDRBG128","JsafeJCE");
		SecureRandom secureRandom4= SecureRandom.getInstance("ECDRBG256","JsafeJCE");
		SecureRandom secureRandom5= SecureRandom.getInstance("MD5PRNG","JsafeJCE");
		SecureRandom secureRandom6= SecureRandom.getInstance("HMACDRBG","JsafeJCE");
		SecureRandom secureRandom7= SecureRandom.getInstance("SHA1PRNG","JsafeJCE");
		
		long starttime;
		long endtime;
		int t = 20000;
		long ave1=0,ave2=0,ave3=0,ave4=0,ave5=0,ave6=0,ave7=0;
		for(int i = 0; i<t;i++)
		{
			//"Windows-PRNG","SunMSCAPI"
			starttime = System.nanoTime();
			secureRandom1.nextInt();
			endtime = System.nanoTime();
			ave1 = ave1 + (endtime-starttime)/t;
			
			
			//"SHA1PRNG","SUN"
			starttime = System.nanoTime();
			secureRandom2.nextInt();
			endtime = System.nanoTime();
			ave2 = ave2 + (endtime-starttime)/t;
			//"ECDRBG128","JsafeJCE"
			starttime = System.nanoTime();
			secureRandom3.nextInt();
			endtime = System.nanoTime();
			ave3 += (endtime-starttime)/t;
			//"ECDRBG256","JsafeJCE"
			starttime = System.nanoTime();
			secureRandom4.nextInt();
			endtime = System.nanoTime();
			ave4 += (endtime-starttime)/t;
			//"MD5PRNG","JsafeJCE"
			starttime = System.nanoTime();
			secureRandom5.nextInt();
			endtime = System.nanoTime();
			ave5 += (endtime-starttime)/t;
			//"HMACDRBG","JsafeJCE"
			starttime = System.nanoTime();
			secureRandom6.nextInt();
			endtime = System.nanoTime();
			ave6 += (endtime-starttime)/t;
			//"SHA1PRNG","JsafeJCE"
			starttime = System.nanoTime();
			secureRandom7.nextInt();
			endtime = System.nanoTime();
			ave7 += (endtime-starttime)/t;
		}
		System.out.println("Windows-PRNG average 1 : " +ave1);
		System.out.println("SHA1PRNG-SUN average 2 : " +ave2);
		System.out.println("ECDRBG128  average 3 :"    +ave3);
		System.out.println("ECDRBG256  average 4 :"    +ave4);
		System.out.println("MD5PRNG    average 5 :"    +ave5);
		System.out.println("HMACDRBG   average 6 :"    +ave6);
		System.out.println("SHA1PRNG-JsafeJCE average 7" + ave7);
		FileWriter fw = new FileWriter("average time.txt",true);
		BufferedWriter bw = new BufferedWriter(fw);
		bw.write("generation amount :" + t);
		bw.newLine();
		bw.write("Windows-PRNG: " + (int) ave1);
		bw.newLine();
		bw.write("SHA1PRNG-SUN: " + (int) ave2);
		bw.newLine();
		bw.write("ECDRBG128: " + (int) ave3);
		bw.newLine();
		bw.write("ECDRBG256: " + (int) ave4);
		bw.newLine();
		bw.write("MD5PRNG : " + (int) ave5);
		bw.newLine();
		bw.write("HMACDRBG: " + (int) ave6);
		bw.newLine();
		bw.write("SHA1PRNG-Jsafe: " + (int) ave7);
		bw.newLine();
		bw.newLine();
		bw.flush();
		bw.close();
		fw.close();
	}

}
