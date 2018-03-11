/**
 * Nakov Chat Server
 * (c) Svetlin Nakov, 2002
 *
 * NakovChatServer class is entry point for the program. It opens a server
 * socket, starts the dispatcher thread and infinitely accepts client connections,
 * creates threads for handling them and starts these threads.
 */

import java.net.*;
import java.io.*;

public class NakovChatServer {
    public static final int LISTENING_PORT = 2004;
    
    public static void main(String[] args) throws Exception{
        // Open server socket for listening
        ServerSocket serverSocket = null;

        try {
           serverSocket = new ServerSocket(LISTENING_PORT);
           System.out.println("NakovChatServer started on port " + LISTENING_PORT);
        } catch (IOException se) {
           System.err.println("Can not start listening on port " + LISTENING_PORT);
           se.printStackTrace();
           System.exit(-1);
        }

        // Start ServerDispatcher thread
        ServerDispatcher serverDispatcher = new ServerDispatcher();
        // Before thread starts, generate key pair for server
        serverDispatcher.makeMyKey();
        serverDispatcher.start();

        // Accept and handle client connections
        while (true) {
           try {
               Socket socket = serverSocket.accept();
               ClientInfo clientInfo = new ClientInfo();
               clientInfo.mSocket = socket;

               ClientListener clientListener = new ClientListener(clientInfo, serverDispatcher);
               ClientSender clientSender = new ClientSender(clientInfo, serverDispatcher);

               clientInfo.mClientListener = clientListener;
               clientInfo.mClientSender = clientSender;
               
               try {
            	   		// check command and key exchange
            	   		serverDispatcher.checkCommand(clientInfo);
               } catch (Exception e) {
            	   		System.out.println("Fail to check command!");
		        	   	System.err.print(e);
					System.exit(-1);
			}
               clientListener.start();
               clientSender.start();
               serverDispatcher.addClient(clientInfo);
               
//               serverDispatcher.display(); ////////////
           } catch (IOException ioe) {
//               ioe.printStackTrace();
        	   		System.err.print(ioe);
				System.exit(-1);
           }
        }        
    }
}