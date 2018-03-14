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
    
    public static void main(String[] args) {
        // open server socket for listening
        ServerSocket serverSocket = null;

        try {
           serverSocket = new ServerSocket(LISTENING_PORT);
           System.out.println("NakovChatServer started on port " + LISTENING_PORT);
        } catch (IOException se) {
           System.err.println(":fail CAN'T START LISTENING ON PORT " + LISTENING_PORT + "\n");
           System.exit(-1);
        }

        // initialize ServerDispatcher thread
        ServerDispatcher serverDispatcher = new ServerDispatcher();
        
        // before thread starts, generate key pair for server
        serverDispatcher.makeMyKey();
        
        // link keystore to chathub
        String ksFileName = args[0];
        String password = args[1];
        serverDispatcher.getMyKeyStore(ksFileName, password);
        
        // start ServerDispatcher thread
        serverDispatcher.start();

        // accept and handle client connections
        while (true) {
           try {
               Socket socket = serverSocket.accept();
               ClientInfo clientInfo = new ClientInfo();
               clientInfo.mSocket = socket;

               ClientListener clientListener = new ClientListener(clientInfo, serverDispatcher);
               ClientSender clientSender = new ClientSender(clientInfo, serverDispatcher);

               clientInfo.mClientListener = clientListener;
               clientInfo.mClientSender = clientSender;

	    	   	   // check command and key exchange
	    	   	   serverDispatcher.checkCommand(clientInfo);
               
               // start clientListener and clientSender thread
               clientListener.start();
               clientSender.start();
               serverDispatcher.addClient(clientInfo);
               
           } catch (IOException ioe) {
        	   		System.err.println(ioe);
           }
        }        
    }
}