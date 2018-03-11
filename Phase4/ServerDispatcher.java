/**
 * Nakov Chat Server
 * (c) Svetlin Nakov, 2002
 *
 * ServerDispatcher class is purposed to listen for messages received
 * from clients and to dispatch them to all the clients connected to the
 * chat server.
 */
import java.io.*;
import java.net.*;
import java.util.*;

public class ServerDispatcher extends Thread {
	private final String myCipherSuite = "ecdh-secp224r1+nocert+AES/CBC/PKCS5Padding";
	private final String keyEstAlgor = "ecdh";		// key establish algorithm
	private final String keyEstSpec = "secp224r1";	// specific parameter for key establish algorithm
	private final String integrity = "nocert";		// a means for ensuring integrity of public key
	private final String symCipher="AES/CBC/PKCS5Padding";		// symmetric cipher
	private KeyExchange myKey;
	
    private Vector<String> mMessageQueue = new Vector<String>();
    private Vector mClients = new Vector();
    
    /**
     * Adds given client to the server's client list.
     */
    public synchronized void addClient(ClientInfo aClientInfo) {
        mClients.add(aClientInfo);
    }

    /**
     * Deletes given client from the server's client list
     * if the client is in the list.
     */
    public synchronized void deleteClient(ClientInfo aClientInfo) {
        int clientIndex = mClients.indexOf(aClientInfo);
        if (clientIndex != -1)
           mClients.removeElementAt(clientIndex);
    }

    /**
     * Adds given message to the dispatcher's message queue and notifies this
     * thread to wake up the message queue reader (getNextMessageFromQueue method).
     * dispatchMessage method is called by other threads (ClientListener) when
     * a message is arrived.
     */
    public synchronized void dispatchMessage(ClientInfo aClientInfo, String aMessage)   {
        Socket socket = aClientInfo.mSocket;
        String senderIP = socket.getInetAddress().getHostAddress();
        String senderPort = "" + socket.getPort();
        aMessage = senderIP + ":" + senderPort + " : " + aMessage;
        mMessageQueue.add(aMessage);
        notify();
    }
    
    /**
     * @return and deletes the next message from the message queue. If there is no
     * messages in the queue, falls in sleep until notified by dispatchMessage method.
     */
    private synchronized String getNextMessageFromQueue() throws InterruptedException  {
        while (mMessageQueue.size()==0)
           wait();
        String message = (String) mMessageQueue.get(0);
        mMessageQueue.removeElementAt(0);
        return message;
    }

    /**
     * Sends given message to all clients in the client list. Actually the
     * message is added to the client sender thread's message queue and this
     * client sender thread is notified.
     */
    private synchronized void sendMessageToAllClients(String aMessage) {    	
        for (int i=0; i<mClients.size(); i++) {
           ClientInfo clientInfo = (ClientInfo) mClients.get(i);		           
           clientInfo.mClientSender.sendMessage(aMessage);
        }
    }
    
    
    /**
     * Infinitely reads messages from the queue and dispatch them
     * to all clients connected to the server.
     */
    public void run()  {
        try {
           while (true) {
               String message = getNextMessageFromQueue();
               sendMessageToAllClients(message);
           }
        } catch (InterruptedException ie) {
           // Thread interrupted. Stop its execution
        }
    }
    
    
    public void checkCommand(ClientInfo aClientInfo) throws Exception {
    		Socket socket = aClientInfo.mSocket;
    		String senderIP = socket.getInetAddress().getHostAddress();
        String senderPort = "" + socket.getPort();
        DataInputStream in = null;
		DataOutputStream out = null;
    		
        // Connect to Nakov Chat Client
    		try {
    			in = new DataInputStream(socket.getInputStream());
    			out = new DataOutputStream(socket.getOutputStream());
            System.out.println("******************* Start command check for " + senderIP + ":" + senderPort + " *******************");
	            
    		} catch (IOException ioe) {
            System.err.println("Can not start command check for " + senderIP + ":" + senderPort);
            ioe.printStackTrace();
            System.exit(-1);
         }
    	
    	
    		// ******************* PHASE 1 initial state ******************* //
		String receivedCipherSuite = null;
		while (receivedCipherSuite == null) {
			// ***** PHASE 1.1: receive :ka cipherSuite ***** //
			try {
				receivedCipherSuite = in.readUTF();
				System.out.println("PHASE 1.1 " + receivedCipherSuite);	
			} catch (Exception err) {
				System.err.println("NO RESPONSE FROM CLIENT!");
				System.exit(-1);
			}
				
			// check whether received command equals to :ka
			String ka = Help.getCommand(receivedCipherSuite);
			try {
				Help.commandEqual(ka, ":ka");	
			} catch (ErrorException fail) {
				System.err.print(fail);
				System.exit(-1);
			}
			
			// check whether received cipher suite include server cipher suite
			String clientCipher = Help.getCipherSuite(receivedCipherSuite);
			try {
				Help.findCipherSuite(myCipherSuite, clientCipher);
			} catch (ErrorException fail) {
				System.err.print(fail);
				System.exit(-1);
			}
			
			finally {
				// ***** PHASE 1.2: send :kaok cipherSuite ***** //
				System.out.println("PHASE 1.2 :kaok "+ myCipherSuite);
				out.writeUTF(":kaok "+ myCipherSuite);
				out.flush();
				
				// ***** PHASE 1.3: send :ka1 based64 encoded public key *****//
				byte[] encodedPublic = myKey.getEncodedPublic();
				byte[] ka1encodedPublic = Help.addKa1(encodedPublic);
				System.out.println("PHASE 1.3 :ka1 "+ encodedPublic.toString());	
				out.writeInt(ka1encodedPublic.length);
				out.write(ka1encodedPublic);
				out.flush();				
			}
		}		
    					
    			// ******************* PHASE 3: waiting for key agreement ******************* //
		int receiveSize = 0;
		while (receiveSize == 0) {
    				// ***** PHASE 3.1: receive :ka1 client's encoded public key ***** //
    				try {
    					receiveSize = in.readInt();
    				} catch (Exception err) {
    					System.err.println("NO RESPONSE FROM CLIENT!");
    					System.exit(-1);
    				}
    				byte[] ka1clientPublic = new byte[receiveSize];
    				in.readFully(ka1clientPublic);
    				System.out.println("PHASE 3.1 :ka1 " + ka1clientPublic.toString());
    				
    				// check whether received command equals to :ka1
    				byte[] ka1 = Help.getKa1(ka1clientPublic);
    				try {
    					Help.commandEqual(ka1, ":ka1 ");
    				} catch (ErrorException fail) {
    					System.err.print(fail);
    					System.exit(-1);
    				}
    				
    				finally {
    					// ***** PHASE 3.2: generate shared secret ***** //
    					myKey.doECDH(Help.splitEncodedPublic(ka1clientPublic));
    					System.out.println("PHASE 3.2 share key: " + myKey.getSecret());
    				}		
    			}
    				
    			// ******************* PHASE 4: chat w/ msg encryption ******************* //	
    			// initialize Encryption object
    			aClientInfo.mEncrption = new Encryption(myKey.getSecret(), symCipher);
    			System.out.println("******************* Finish command check for " + senderIP + ":" + senderPort + " *******************");
    }
    
    /**
     * initialize KeyExchange object myKey with given cipher suite and ClientInfo
     * 
     * @param the cipher suite sent by client, and ClientInformation
     */
    public void makeMyKey() throws Exception {
		myKey = new KeyExchange(keyEstAlgor, keyEstSpec, integrity);
	}
    
}