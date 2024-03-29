import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
//ref:http://docs.oracle.com/javase/1.5.0/docs/api/
import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
public class HMACSHAClient2 {
	private static int Serverport;
	private static DatagramSocket socket;
	private static InetAddress ServerIpAddress;
	// create  new account
	public static boolean createaccount() throws IOException
	{	
		boolean saved = false;
		System.out.println("enter the account you want use");
		String account = easyscanner.nextString();
		if(getaccount(account).equals("No Such Account"))
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
	
	public static String getaccount(String accountinput) throws IOException{
		String userinfo = "";

		userinfo = Send_Receive("Request Userinfo:" + accountinput);
		System.out.println(userinfo);
		return userinfo;
	}
	//save the accountinfo into data.txt, the info format depends on the function 
	// return true for saved successful, false for unsuccessful
	public static boolean SaveaccountInfo(String accountinfo) throws IOException
	{
		boolean saved = false;
		String account = accountinfo.split(":")[0];
		String key = accountinfo.split(":")[2];
		String Clientinfo = account + ":" + key;
		try
		{
			FileWriter fw = new FileWriter("data_client_key.txt",true);
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(Clientinfo);
			bw.newLine();
			bw.flush();
			bw.close();
			fw.close();
		}catch(IOException e){}
		
		String Respons =  Send_Receive("Save Accountinfo:" + accountinfo);
		if(Respons.equals("Userinfo Saved Successful"))
		{
			saved = true;
		}
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
	//generate the SSHA hash
	//@param: @param1 password  @param2 salts(generated by function generatesalts)
	//return: the digest of password
	public static byte[] generateHashwithsalt(String password, byte[] salts){
		byte[] digest = new byte[0];
		try{
			MessageDigest hash = MessageDigest.getInstance("SHA-1");
			hash.update(password.getBytes("UTF-8"));
			digest = hash.digest(salts);
		}
		catch(IOException e){} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return digest;
		
		
	}
	// generate the salt used in function generateHshwithsalt()
	//return: salt
	public static byte[] generatesalts(){
		SecureRandom random;
		byte[] salt = new byte[8];
		try{
			random = SecureRandom.getInstance("SHA1PRNG");
			random.nextBytes(salt);
		}catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return salt;
		
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
	//generate the userdatainfor by SSHA algorithm
	//@param: @param1: useraccount @param2: user's password
	//return: return the userdata to be saved, the format is useraccount:salt(BASE64) password's digest(BASE64)
	public static String generateUserData_SSHA(String accountin,String passwordin) throws UnsupportedEncodingException{
		byte[] salt = generatesalts();
		byte[] digest_SSHA = generateHashwithsalt(passwordin,salt);
		String salt_BASE64 = new sun.misc.BASE64Encoder().encode(salt);
		String digestBASE64_SSHA = new sun.misc.BASE64Encoder().encode(digest_SSHA);
		return accountin + ":" + salt_BASE64 + ":" + digestBASE64_SSHA;
		
	}
	// generate the userdatainfor by HMACSHA1
	//@param: @param1: useraccount @param2: user's password
	


	public static String getKey(String accountin)
	{
		String key = "";
		try{
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("data_client_key.txt")));
			String accounts = br.readLine();
			if(accounts == null)
			{
				key = "No Such Account";
			}
			else
			{
				do
				{
					if(accountin.equals(accounts.split(":")[0]))
					{
						key = accounts.split(":")[1];
					}
				}while((accounts = br.readLine()) != null);
			}
			br.close();
		}catch(IOException e){}
		return key;
	}
	public static String generateUserData_HMACSHA1(String accountin,String passwordin) throws UnsupportedEncodingException 
	{	
		byte[] key = generatekey();
		byte[] digest_HMACSHA1 = generateHashwithoutsalt(passwordin,key);
		String keyBASE64 =  new sun.misc.BASE64Encoder().encode(key);
		String digestBASE64_HMACSHA1 = new sun.misc.BASE64Encoder().encode(digest_HMACSHA1);
		return accountin + ":" + digestBASE64_HMACSHA1 + ":" + keyBASE64;		
	}
	public static String authentication_HMAC(String accountin,String passwordin) throws IOException
	{	
		String key = "";
		try
		{
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("data_client_key.txt")));
			String accounts = "";
			accounts = br.readLine();
			if(accounts == null)
			{}
			else
			{
				do
				{
					if(accountin.equals(accounts.split(":")[0]))
					{
						key = accounts.split(":")[1];
					}
				}while((accounts = br.readLine()) != null);
			}
		}catch(IOException e){}
		String result = "";
		System.out.println("KEY IS" + key);
		byte[] b_key = new sun.misc.BASE64Decoder().decodeBuffer(key);
		byte[] passwordhash = generateHashwithoutsalt(passwordin,b_key);
		String passwordhashBASE64 = new sun.misc.BASE64Encoder().encode(passwordhash);
		result = Send_Receive("Authentication:" + accountin + ":" + passwordhashBASE64);
		return result;
	}
	//ref:http://www.cnblogs.com/ningbj/articles/2329560.html
	private static String Send_Receive(String Datain) throws IOException
	{
		byte[] SendData = Datain.getBytes("UTF-8");
		DatagramPacket sendPacket = new DatagramPacket(SendData,SendData.length,ServerIpAddress,Serverport);
		socket.send(sendPacket);
		byte[] receivebuf = new byte[1024];
		DatagramPacket receivePacket = new DatagramPacket(receivebuf,receivebuf.length);
		socket.receive(receivePacket);
		String str = new String(receivebuf,0,receivePacket.getLength());
		return str;
	}
	public static void main(String[] args) throws IOException
	{	
		System.out.println("enter server IP Address : ");
		String ServerIp = easyscanner.nextString();
		ServerIpAddress = InetAddress.getByName(ServerIp);
		System.out.println("enter the port number");
		String port = easyscanner.nextString();
		Serverport = Integer.parseInt(port);
		socket = new DatagramSocket();
		System.out.println("Server IP :" + ServerIp);
		System.out.println("Server port : " + port);
		

		boolean success = false;
		String choice2 = "r";
		String choice1 = "n";
		do{
			

			System.out.println("enter you account");
			String accountin = easyscanner.nextString();
			if(getaccount(accountin).equals("No Such Account"))
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
			else 
			{	
				System.out.println("Enter your password");
				String passwordin = easyscanner.nextString();
				if(authentication_HMAC(accountin,passwordin).equals("Authentication Successful"))
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