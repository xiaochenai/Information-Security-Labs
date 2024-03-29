import java.io.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import biz.source_code.base64Coder.Base64Coder;
public class Sha1_SSHA {
	// create  new account
	public static boolean createaccount() throws UnsupportedEncodingException, NoSuchAlgorithmException
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
				String accountinfo = generateUserData_SSHA(account,pasw1);
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
			
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("data_SSHA.txt")));
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
			FileWriter fw = new FileWriter("data_SSHA.txt",true);
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(accountinfo);
			bw.newLine();
			bw.flush();
			bw.close();
			fw.close();
		}catch(IOException e){}
		
		try
		{
			RandomAccessFile rf = new RandomAccessFile("data.txt","r");
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
	//generate the SSHA hash
	//@param: @param1 password  @param2 salts(generated by function generatesalts)
	//return: the digest of password
	public static byte[] generateHashwithsalt(String password, byte[] salts) throws NoSuchAlgorithmException{
		byte[] digest = new byte[0];
		MessageDigest hash = MessageDigest.getInstance("SHA-1");
		try{
			
			hash.reset();
			hash.update(salts);
			digest = hash.digest(password.getBytes("UTF-8"));
		}
		catch(IOException e){}
		for (int i = 0; i < 1000; i++)
		{
			hash.reset();
			digest = hash.digest(digest);
		}
		return digest;
		
		
	}
	// generate the salt used in function generateHshwithsalt()
	//return: salt
	public static byte[] generatesalts(){
		SecureRandom random;
		byte[] salt = new byte[12];
		try{
			random = SecureRandom.getInstance("SHA1PRNG");
			random.nextBytes(salt);
		}catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return salt;
		
	}
	//generate the userdatainfor by SSHA algorithm
	//@param: @param1: useraccount @param2: user's password
	//return: return the userdata to be saved, the format is useraccount:salt(BASE64) password's digest(BASE64)
	public static String generateUserData_SSHA(String accountin,String passwordin) throws UnsupportedEncodingException, NoSuchAlgorithmException{
		byte[] salt = generatesalts();
		
		byte[] digest_SSHA = generateHashwithsalt(passwordin,salt);
		String salt_BASE64 = Base64Coder.encodeLines(salt);
		
		String digestBASE64_SSHA = Base64Coder.encodeLines(digest_SSHA);
		return accountin + ":" + salt_BASE64.replace("\n", "").trim() + ":" + digestBASE64_SSHA.replace("\n", "").trim();
		
		
	}

	
	
	public static boolean authentication_SSHA(String accountin,String passwordin) throws NoSuchAlgorithmException
	{
		boolean result = false;
		String[] InfoArray = getaccount(accountin).split(":");
		String salt = InfoArray[1];//the salt use to get the passwordin's hash
		String hash = InfoArray[2];// this hash is the stored pasword's hash
		byte[] bsalt = Base64Coder.decodeLines(salt);
		byte[] ehash = generateHashwithsalt(passwordin,bsalt);//get the passwordin's hash
		String ehashBASE64 = Base64Coder.encodeLines(ehash);
		
		
		System.out.println("Stored salt : " + salt);
		System.out.println("input Hash  : " + ehashBASE64);
		System.out.println("Stored Hash : " + hash);
		
		if(ehashBASE64.replace("\n", "").trim().equals(hash)){
			result = true;
		}
		return result;
	}

	public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException
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
			else if(!getaccount(accountin).equals("No Such Account") )
			{	
				System.out.println("Enter your password");
				String passwordin = easyscanner.nextString();
				if(authentication_SSHA(accountin,passwordin))
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
