/**
 * Nakov Chat Server - (c) Svetlin Nakov, 2002
 *
 * ClientListener class is purposed to listen for client messages and
 * to forward them to ServerDispatcher.
 */
import java.io.*;
import java.net.*;

public class ClientListener extends Thread {
    private ServerDispatcher mServerDispatcher;
    private ClientInfo mClientInfo;
    private BufferedReader mIn;
 
    public ClientListener(ClientInfo aClientInfo, ServerDispatcher aServerDispatcher) throws IOException {
        mClientInfo = aClientInfo;
        mServerDispatcher = aServerDispatcher;
        Socket socket = aClientInfo.mSocket;
        mIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }
    
    /**
     * Until interrupted, reads messages from the client socket, forwards them
     * to the server dispatcher's queue and notifies the server dispatcher.
     */
    public void run()  {
    	String message = null;
    	String ciphertext = null;
        try {
		   while (!isInterrupted()) {
		   		ciphertext = mIn.readLine();
		   		try {
		   			message = mClientInfo.mEncrption.decrypt(ciphertext);
				} catch (Exception e) {
					System.err.print(e);
					System.exit(-1);
				}
				finally {
					// display received message
					System.out.println(message);    				
					// display the encrypted message from client before decryption
					System.out.println("(Decrypted from cipher text: " + ciphertext + ")");			
				}
		   		
	          if (message == null || message.equals("exit"))
	               break;
	          mServerDispatcher.dispatchMessage(mClientInfo, message);
           }
        } catch (IOException ioex) {
           // Problem reading from socket (communication is broken)
        }

        // Communication is broken. Interrupt both listener and sender threads        
        String senderIP = mClientInfo.mSocket.getInetAddress().getHostAddress();
        String senderPort = "" + mClientInfo.mSocket.getPort();
        System.out.println("Bye! " + senderIP + " " + senderPort);

        mClientInfo.mClientSender.interrupt();
        mServerDispatcher.deleteClient(mClientInfo);
        try {
        		mClientInfo.mSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
}

 