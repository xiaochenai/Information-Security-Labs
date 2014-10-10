
//finish Step 4 
//@author Xiao Lin @2012/08/20
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
public class HMACSHA {
	// create  new account
	public static boolean createaccount() throws UnsupportedEncodingException
	{	
		boolean saved = false;
		System.out.println("enter the account you want use");
		String account = easyscanner.nextString();
		if(getaccount(account)==("No Such Account"))
		{
			System.out.println("enter the password");
			String pasw1 = easyscanner.nextString();
			System.out.println("confirm you password again");
			String pasw2 = easyscanner.nextString();
			if(pasw1.equals(pasw2))
			{
				String accountinfo = generateUserData_HMACSHA1(account,pasw1);
				saved = SaveaccountInfo(accountinfo);
				return saved;
			}
			else
			{
				System.out.println("twice password do not equal each other");
				return false;
			}
		}
		else
		{
			System.out.println("Account already exist");
			return false;
		}
		
	}
	
	// check if the account has exist, 
	// return: true for yes, false for no
	
	public static String getaccount(String accountinput){
		String userinfo = "No Such Account";
		try{
			
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("data_HMAC.txt")));
			String accounts = "";
			accounts = br.readLine();
			if(accounts == null)
			{
				userinfo = "No Such Account";
			}
			else
			{
				do
				{	
					
					//System.out.println((accounts.split(":")[0]));
					if(accountinput.equals(accounts.split(":")[0]))
					{	
						userinfo = accounts;
					}
	
				}while((accounts = br.readLine()) != null);
			}
			
			br.close();
		}
		catch(IOException e){}

		
		return userinfo;
	}
	//save the accountinfo into data.txt, the info format depends on the function 
	// return true for saved successful, false for unsuccessful
	public static boolean SaveaccountInfo(String accountinfo)
	{
		boolean saved = false;
		
		try
		{	
			FileWriter fw = new FileWriter("data_HMAC.txt",true);
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(accountinfo);
			bw.newLine();
			bw.flush();
			bw.close();
			fw.close();
		}catch(IOException e){}
		
		try
		{
			RandomAccessFile rf = new RandomAccessFile("data_HMAC.txt","r");
			long length = rf.length();
			long start = rf.getFilePointer();
			long nextend = start + length -2;
			rf.seek(nextend);
			String line = rf.readLine();
			if(line.equals(accountinfo))
			{
				saved = true;
			}
		}catch(IOException e){}
		return saved;
		
		
	}
	//ref:http://www.exampledepot.com/egs/javax.crypto/GenMac.html
	// generate HMACSHA1 HASH
	//return: the digest of password
	public static byte[] generateHashwithoutsalt(String password,byte[] key) throws UnsupportedEncodingException{
		byte[] digest = new byte[0];

		try{
			SecretKey secretekey = new SecretKeySpec(key,"HmacSHA1");
			Mac mac = Mac.getInstance(secretekey.getAlgorithm());
			mac.init(secretekey);
			
			byte[] utf8 = password.getBytes("UTF-8");
			digest = mac.doFinal(utf8);
			
			

			
		}catch(InvalidKeyException e){}
		catch(NoSuchAlgorithmException e){}
		
		return digest;
		
	}


	public static byte[] generatekey(){
		SecureRandom random;
		byte[] key = new byte[8];
		try{
			random = SecureRandom.getInstance("SHA1PRNG");
			random.nextBytes(key);
		}catch(NoSuchAlgorithmException e){}
		
		return key;
	}
	
	// generate the userdatainfor by HMACSHA1
	//@param: @param1: useraccount @param2: user's password
	
	public static String generateUserData_HMACSHA1(String accountin,String passwordin) throws UnsupportedEncodingException 
	{	
		byte[] key = generatekey();
		byte[] digest_HMACSHA1 = generateHashwithoutsalt(passwordin,key);
		String keyBASE64 =  new sun.misc.BASE64Encoder().encode(key);
		String digestBASE64_HMACSHA1 = new sun.misc.BASE64Encoder().encode(digest_HMACSHA1);
		return accountin + ":" + digestBASE64_HMACSHA1 + ":" + keyBASE64;		
	}

	public static boolean authentication_HMAC(String accountin,String passwordin)
	{
		boolean result = false;
		try{
			
				String[] InfoArray = getaccount(accountin).split(":");
				String key = InfoArray[2];
				byte[] b_key =  new sun.misc.BASE64Decoder().decodeBuffer(key);
				String hash = InfoArray[1];//the key use to get the passwordin's hash
				byte[] ehash = generateHashwithoutsalt(passwordin,b_key);//get the passwordin's hash
				String ehashBASE64 = new sun.misc.BASE64Encoder().encode(ehash);
				
				
				System.out.println("input Hash  : " + ehashBASE64);
				System.out.println("Stored Hash : " + hash);
				System.out.println("Stored Key  : " + key);
				
				if(ehashBASE64.equals(hash)){
					result = true;
				}
				
				
			
		}catch(IOException e){}
		return result;
	}
	public static void main(String[] args) throws UnsupportedEncodingException
	{	
		boolean success = false;
		String choice2 = "r";
		String choice1 = "n";
		do{
			

			System.out.println("enter you account");
			String accountin = easyscanner.nextString();
			if(getaccount(accountin)=="No Such Account")
			{
				System.out.println("No Such Account Exist");
				System.out.println("Do you want to create new account? enter y for yes, n for no");
				choice1 = easyscanner.nextString();
				if(choice1.equals("y"))
				{	
					success = createaccount();
				}
				if(choice1.equals("n"))
				{	
					System.out.println("enter e to exit, enter r to restart");
					choice2 = easyscanner.nextString();
					
				}
			}
			else if(!getaccount(accountin).equals("No Such Account"))
			{	
				System.out.println("Enter your password");
				String passwordin = easyscanner.nextString();
				if(authentication_HMAC(accountin,passwordin))
				{
					System.out.println("Authentication Successful");
				}
				else{
					System.out.println("Authentication Failed");
				}
			}
			if(success == false && choice1 != "n")
			{
				System.out.println("enter e to exit, enter r to restart");
				choice2 = easyscanner.nextString();
			}
		}while(choice2.equals("r"));
	}
	
	

}