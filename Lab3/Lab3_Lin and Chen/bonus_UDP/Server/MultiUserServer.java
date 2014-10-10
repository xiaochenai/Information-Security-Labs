
import java.net.*;
import java.io.*;


public class MultiUserServer
{
	public static void main( String[] args ) throws IOException
	{
		DatagramSocket serverSocket = null;
		boolean listening = true;
		boolean request = false;
		try
		{
			serverSocket = new DatagramSocket(8888);
		}
		catch (IOException e)
		{
			System.out.println("Could not listen on port: 8888");
			System.exit(-1);
		}
		System.out.println("Waiting for packets...\n");
		while (listening)
		{
			request = serverSocket.isBound();
			if (request)
			{
				new MultiUserServerThread(serverSocket).run();
				request = false;
			}

		}
		serverSocket.close();
	}
} 
