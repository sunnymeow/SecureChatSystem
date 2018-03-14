/**
 * Nakov Chat Server - (c) Svetlin Nakov, 2002
 *
 * ClientSender class is proposed to send messages to the client. Messages are 
 * stored in a message queue. When the queue is empty, ClientSender falls in 
 * sleep until a new message is arrived in the queue. When the queue is not 
 * empty, ClientSender sends the messages from the queue to the client socket.
 */
import java.io.*;
import java.net.*;
import java.util.*;

public class ClientSender extends Thread{
    private Vector<String> mMessageQueue = new Vector<String>();
    private ServerDispatcher mServerDispatcher;
    private ClientInfo mClientInfo;
    private PrintWriter mOut;
 
    public ClientSender(ClientInfo aClientInfo, ServerDispatcher aServerDispatcher) throws IOException {
        mClientInfo = aClientInfo;
        mServerDispatcher = aServerDispatcher;
        Socket socket = aClientInfo.mSocket;
        mOut = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
    }

    /**
     * Adds given message to the message queue and notifies this thread
     * (actually getNextMessageFromQueue method) that a message is arrived.
     * sendMessage is called by other threads (ServeDispatcher).
     */
    public synchronized void sendMessage(String aMessage) {
        mMessageQueue.add(aMessage);
        notify();
    }

    /**
     * @return and deletes the next message from the message queue. If the queue
     * is empty, falls in sleep until notified for message arrival by sendMessage
     * method.
     */
    private synchronized String getNextMessageFromQueue() throws InterruptedException {
        while (mMessageQueue.size()==0)
           wait();
        String message = (String) mMessageQueue.get(0);
        mMessageQueue.removeElementAt(0);
        return message; 
    }

    /**
     * Until interrupted, reads messages from the message queue
     * and sends them to the client's socket.
     */
    public void run() {
    		String message = null;
    		String ciphertext = null;
        try {
           while (!isInterrupted()) {
        	   	   // encryption
               message = getNextMessageFromQueue();
               ciphertext = mClientInfo.mEncrption.encrypt(message);
               System.out.println(message);
               System.out.println("\t(Encrypted into cipher text: " + ciphertext + ")");
               
               // send encrypted message to client socket
               mOut.println(ciphertext);
               mOut.flush();
           }
        } catch (InterruptedException e) {
        		System.err.println(e);
		}   
        
        // Communication is broken. Interrupt both listener and sender threads
        mClientInfo.mClientListener.interrupt();
		mServerDispatcher.deleteClient(mClientInfo);

    }
}

