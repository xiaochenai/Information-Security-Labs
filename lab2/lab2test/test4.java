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
public class test4 {
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException{
		/*
		KeyGenerator Key1 = KeyGenerator.getInstance("AES");
		KeyGenerator Key2 = KeyGenerator.getInstance("AES");
		KeyGenerator Key3 = KeyGenerator.getInstance("AES");
		KeyGenerator Key4 = KeyGenerator.getInstance("AES");
		*/
		SecureRandom secureRandom1 = SecureRandom.getInstance("Windows-PRNG","SunMSCAPI");
		SecureRandom secureRandom2 = SecureRandom.getInstance("SHA1PRNG","SUN");
		SecureRandom secureRandom3 = SecureRandom.getInstance("ECDRBG128","JsafeJCE");
		SecureRandom secureRandom4= SecureRandom.getInstance("ECDRBG256","JsafeJCE");
		SecureRandom secureRandom5= SecureRandom.getInstance("MD5PRNG","JsafeJCE");
		SecureRandom secureRandom6= SecureRandom.getInstance("HMACDRBG","JsafeJCE");
		SecureRandom secureRandom7= SecureRandom.getInstance("SHA1PRNG","JsafeJCE");
		
		long starttime;
		long endtime;
		FileWriter fw = new FileWriter("average_3.txt",true);
		BufferedWriter bw = new BufferedWriter(fw);
		int[] t = {1,10,15,20,30,40,50,100,200,300,400,500,600,700,800,900,1000,2000,3000,4000,5000,6000,7000,8000,9000,10000,12000,14000,
				16000,18000,20000};
		byte[] bytes = new byte[1024/8];
		double ave1=0,ave2=0,ave3=0,ave4=0,ave5=0,ave6=0,ave7=0;
		double period=0;
		for(int i = 0;i < t.length;i++)
		{
			bw.write(t[i] + " ");
		}
		bw.newLine();
		for(int i=0;i<t.length;i++)
		{	
			ave1 = 0;
			for(int j=0;j<t[i];j++)
			{
				starttime = System.nanoTime();
				secureRandom1.nextBytes(bytes);
				endtime = System.nanoTime();
				period = (endtime-starttime);
				ave1 = ave1 + period/t[i];
			}
			bw.write(ave1 + " ");
		}
		bw.newLine();
		for(int i=0;i<t.length;i++)
		{	
			ave2 = 0;
			for(int j=0;j<t[i];j++)
			{
				starttime = System.nanoTime();
				secureRandom2.nextBytes(bytes);
				endtime = System.nanoTime();
				period = endtime -starttime;
				ave2 = ave2 + period/t[i];
			}
			bw.write(ave2 + " ");
		}		
		bw.newLine();
		for(int i=0;i<t.length;i++)
		{	
			ave3 = 0;
			for(int j=0;j<t[i];j++)
			{
				starttime = System.nanoTime();
				secureRandom3.nextBytes(bytes);
				endtime = System.nanoTime();
				period = endtime -starttime;
				ave3 = ave3 + period/t[i];
			}
			bw.write(ave3 + " ");
		}
		bw.newLine();
		for(int i=0;i<t.length;i++)
		{	
			ave4 = 0;
			for(int j=0;j<t[i];j++)
			{
				starttime = System.nanoTime();
				secureRandom4.nextBytes(bytes);
				endtime = System.nanoTime();
				period = endtime -starttime;
				ave4 = ave4 + period/t[i];
			}
			bw.write(ave4 + " ");
		}
		bw.newLine();
		for(int i=0;i<t.length;i++)
		{	
			ave5 = 0;
			for(int j=0;j<t[i];j++)
			{
				starttime = System.nanoTime();
				secureRandom5.nextBytes(bytes);
				endtime = System.nanoTime();
				period = endtime -starttime;
				ave5 = ave5 + period/t[i];
			}
			bw.write(ave5 + " ");
		}
		bw.newLine();
		for(int i=0;i<t.length;i++)
		{	
			ave6 = 0;
			for(int j=0;j<t[i];j++)
			{
				starttime = System.nanoTime();
				secureRandom6.nextBytes(bytes);
				endtime = System.nanoTime();
				period = endtime -starttime;
				ave6 = ave6 + period/t[i];
			}
			bw.write(ave6 + " ");
		}
		bw.newLine();
		for(int i=0;i<t.length;i++)
		{	
			ave7 = 0;
			for(int j=0;j<t[i];j++)
			{
				starttime = System.nanoTime();
				secureRandom7.nextBytes(bytes);
				endtime = System.nanoTime();
				period = endtime -starttime;
				ave7 = ave7 + period/t[i];
			}
			bw.write(ave7 + " ");
		}
		
		
		
		
		
		System.out.println("finish");
		bw.flush();
		bw.close();
		fw.close();
	}

}

