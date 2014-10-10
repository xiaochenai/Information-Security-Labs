package server;

import java.net.*;

import java.io.*;

public class MultiUserServerThread extends Thread
{
	private DatagramSocket socket = null;


	public MultiUserServerThread( DatagramSocket socket )
	{
		this.socket = socket;
	}

	public void run()
	{
		while(true)
		{
		//attention: the receive buffer is just 1024byte, so can not handle data bigger than 1024 bytes
		byte[] receivebuf = new byte[1024];
		byte[] sendbuf;
		
		DatagramPacket packet = new DatagramPacket(receivebuf,receivebuf.length);
		
		try{
			
			socket.receive(packet);
			
			String ReceiveData = new String(receivebuf,0,packet.getLength());
			System.out.println("receive data from client:" + ReceiveData);
			String command = ReceiveData.substring(0,ReceiveData.indexOf(":"));
			String UserData = ReceiveData.substring(ReceiveData.indexOf(":")+1);
			
			// estimate the command sent by Client
			if(command.equals("Request Userinfo"))
			{	
				String[] UserAccountin = UserData.split(":"); 
				String UserInfo = GetUserInfo(UserAccountin[0]);
				sendbuf = UserInfo.split(":")[0].getBytes("UTF-8");
				packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
				try
				{
					socket.send(packet);
				}catch(IOException e){}
				System.out.println("Reply the Request for Userinfo :" + UserInfo.split(":")[0]);
			}
			else if(command.equals("Save Accountinfo"))
			{
				String respons = SaveUserInfo(UserData);
				sendbuf = respons.getBytes("UTF-8");
				packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
				try
				{
					socket.send(packet);
				}catch(IOException e){}
				System.out.println(respons);
			}
			else if(command.equals("Authentication"))
			{	
				String accountin = UserData.split(":")[0];
				String passwordhash = UserData.split(":")[1];
				String respons = authentication_HMAC(accountin,passwordhash);
				sendbuf = respons.getBytes("UTF-8");
				packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
				try
				{
					socket.send(packet);
				}catch(IOException e){}
				System.out.println(respons);
				System.out.println();
			}
			else
			{
				System.out.println("No Such Command");
			}
			
		}catch(IOException e){}
	}
	}


	//get the user information by username, user information contains username, hash of password, key
	//@param: username
	//@return: String of user information\
	// the return String's format likes this: username:password:key
	public static String GetUserInfo(String accountin){
		String userinfo = "No Such Account";
		try
		{
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("data_server.txt")));
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
					if(accountin.equals(accounts.split(":")[0]))
					{
						userinfo = accounts;
					}
					
				}while((accounts = br.readLine()) != null);
			}
			br.close();
		}catch(IOException e){}
		
		return userinfo;
		
		
	}
	//save user information in Server
	//@param: userdata
	//@return: a String indicate whether save successful
	public static String SaveUserInfo(String UserDatain)
	{	
		String result = "Data Saved Unsuccessful";
		try
		{
			FileWriter fw = new FileWriter("data_server.txt",true);
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(UserDatain);
			bw.newLine();
			bw.flush();
			bw.close();
			fw.close();
			result = "Data Saved";
			
		}catch(IOException e){}
		
		
		return result;
	}
	//check if the password's hash sent by Client match the stored password's hash
	//@param: @param1 account   @param2: passwordhash
	//@reutrn: result String indicates whether match
	public static String authentication_HMAC(String accountin, String passwordhash) throws IOException
	{
		String result = " " ;
		
		String[] InfoArray = GetUserInfo(accountin).split(":");
		String key = InfoArray[2];
		String hash = InfoArray[1];

		
		System.out.println("Account:"+accountin);
		System.out.println("SHash: " +hash);
		System.out.println("RHash: "+ passwordhash);
		System.out.println("KEY IS :" + key);
	
		byte[] b_a = hash.getBytes("UTF-8");
		byte[] b_b = passwordhash.getBytes("UTF-8");
		String a = new String(hash.getBytes("UTF-8"));
		String b = new String(passwordhash.getBytes("UTF-8"));
		a.replace("\n","").trim();
		b.replace("\n","").trim();
		
		if(a.equals(b))
		{
			result = "Authentication Successful";
		}
		System.out.println("");

		
		
		
		return result;
		
		
	}
}