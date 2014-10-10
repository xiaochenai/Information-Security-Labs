package com;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

//ref:http://www.cnblogs.com/ningbj/articles/2329560.html
public class Server2 {
	public static void main(String[] args)
	{	
		while(true)
		{
		byte[] receivebuf = new byte[1024];
		byte[] sendbuf;
		
		DatagramPacket packet = new DatagramPacket(receivebuf,receivebuf.length);
		
		try{
			DatagramSocket socket = new DatagramSocket(8888);
			socket.receive(packet);
			
			String ReceiveData = new String(receivebuf,0,packet.getLength());
			System.out.println("receive data :" + ReceiveData);
			String command = ReceiveData.substring(0,ReceiveData.indexOf(":"));
			String UserData = ReceiveData.substring(ReceiveData.indexOf(":")+1);
			
			if(command.equals("Request Userinfo"))
			{	
				String[] UserAccountin = UserData.split(":"); 
				String UserInfo = GetUserInfo(UserAccountin[0]);
				sendbuf = UserInfo.getBytes("UTF-8");
				packet = new DatagramPacket(sendbuf,sendbuf.length,packet.getAddress(),packet.getPort());
				try
				{
					socket.send(packet);
				}catch(IOException e){}
				System.out.println("Reply the Request for Userinfo :" + UserInfo);
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
			}
			else
			{
				System.out.println("No Such Command");
			}
			
		}catch(IOException e){}
	}
	}
	
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
			
		}catch(IOException e){}
		
		try
		{
			RandomAccessFile rf = new RandomAccessFile("data_server.txt","r");
			long length = rf.length();
			long start = rf.getFilePointer();
			long nextend = start + length - 2;
			rf.seek(nextend);
			String line = rf.readLine();
			if(line.equals(UserDatain))
			{
				result = "Userinfo Saved Successful";
			}
		}catch(IOException e){}
		return result;
	}
	
	public synchronized static String authentication_HMAC(String accountin, String passwordhash) throws IOException
	{
		String result = " " ;
		
		String[] InfoArray = GetUserInfo(accountin).split(":");
		String key = InfoArray[2];
		String hash = InfoArray[1];

		
		System.out.println("Account:"+accountin);
		System.out.println("Stored Hash: " +hash);
		System.out.println("Received Hash: "+ passwordhash);
		System.out.println("KEY  :" + key);
	
		byte[] b_a = hash.getBytes("UTF-8");
		byte[] b_b = passwordhash.getBytes("UTF-8");
		String a = new String(hash.getBytes("UTF-8"));
		String b = new String(passwordhash.getBytes("UTF-8"));
		a.replace("\n","").trim();
		b.replace("\n","").trim();
		System.out.println("a:"+hash.length()+"b:"+b.length());
		if(a.equals(b))
		{
			result = "Authentication Successful";
		}

		
		
		//System.out.println("Authentication result" + result);
		return result;
		
		
	}
	
}