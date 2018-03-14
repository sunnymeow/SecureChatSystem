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
import java.security.*;
import java.util.*;

public class ServerDispatcher extends Thread {
	private final static String myCipherSuite = "ecdh-secp224r1+X.509+AES_128/GCM/NoPadding";			// for AES/GCM
	private final static String symCipher="AES_128/GCM/NoPadding";									// symmetric cipher for AES/GCM
//	private final static String myCipherSuite = "ecdh-secp224r1+X.509+AES/CBC/PKCS5Padding";			// for AES/CBC
//	private final static String symCipher="AES/CBC/PKCS5Padding";										// symmetric cipher for AES/CBC
	private final static String keyEstAlgor = "ecdh";					// key establish algorithm
	private final static String keyEstSpec = "secp224r1";				// specific parameter for key establish algorithm
	private final static String integrity = "X.509";					// a means for ensuring integrity of public key
	private KeyExchange myKey;
	private KeyStore myKeyStore;
	private String myAlias;
	
    private static Vector <String> mMessageQueue = new Vector <String> (); 
    private static HashMap <String, ClientInfo> mClients = new HashMap <String, ClientInfo>();		// Hashmap <alias, ClientInfo>
    
    /**
     * Adds given client to the server's client list.
     */
    public synchronized void addClient(ClientInfo aClientInfo) {
        mClients.put(aClientInfo.mAlias, aClientInfo);
    }

    /**
     * Deletes given client from the server's client list
     * @throws IOException 
     */
    public synchronized void deleteClient(ClientInfo aClientInfo) {
    		if (mClients.containsKey(aClientInfo.mAlias))
    			mClients.remove(aClientInfo.mAlias);
    }

    /**
     * Adds given message to the dispatcher's message queue and notifies this
     * thread to wake up the message queue reader (getNextMessageFromQueue method).
     * dispatchMessage method is called by other threads (ClientListener) when
     * a message is arrived.
     */
    public synchronized void dispatchMessage(ClientInfo aClientInfo, String aMessage)   {
    		aMessage = aClientInfo.mAlias + "/" + aMessage;
    		mMessageQueue.add(aMessage);
    		notify();
    }

    /**
     * @return and deletes the next message from the message queue. If there is no
     * messages in the queue, falls in sleep until notified by dispatchMessage method.
     */
    private synchronized String getNextMessageFromQueue() throws InterruptedException {
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
    		for(Map.Entry<String, ClientInfo> entry: mClients.entrySet()) {
           ClientInfo clientInfo = entry.getValue();		           
           clientInfo.mClientSender.sendMessage(aMessage);
        }
    }
    
    /**
     * Sends given message to all clients in the client list. Actually the
     * message is added to the client sender thread's message queue and this
     * client sender thread is notified.
     * @throws InterruptedException 
     */
    private synchronized void sendMessageToClients(String message) {  
    		String[] getSender = message.split("/");
    		String senderAlias = getSender[0];
    		message = getSender[1];
    		
    		if (message.contains(":")) {
	    	     // extract receiver from message
	    	     String[] split = message.split("\\:");
	    	     String toRec = split[0];
	    	     String receiverAlias = toRec.split(" ")[1];
	    	     message = split[1];
	    	     System.out.println(receiverAlias);
	    	     System.out.println(message);
	    	     
	    	     // attach sender alias preceded the message
	    	     String newMsg = "From " + senderAlias + " : " + message;
	    	     
	    	     if (receiverAlias.toLowerCase().equals("all")) {
	    	    	 	sendMessageToAllClients(newMsg);
	    	     } 
	    	     else {
	    	    	 	String feedback = "**** Message has been sent to " + receiverAlias + " ****";
	    	    	 
	    	    	 	// receiver alias is not found in client list, send back to sender
	    	    	 	if (mClients.get(receiverAlias)==null) {
	    	    	 		newMsg = ":err CAN'T FIND CLIENT ALIAS NAME " + receiverAlias + " IN CHAT HUB CLIENT LIST! PLEASE REDO!";
	    	    	 		feedback = "**** Message FAILED to send to " + receiverAlias + " ****";
	    	    	 		receiverAlias = senderAlias;
	    	    	 	}
	    	    	 	ClientInfo receiver = mClients.get(receiverAlias); 
	    	    	 	receiver.mClientSender.sendMessage(newMsg);
	    	    	 	ClientInfo sender = mClients.get(senderAlias);
	    	    	 	sender.mClientSender.sendMessage(feedback);
	    	     	}
    		}
	    else {
	    		// message in wrong format, send back to sender
	    		String newMsg = ":err MESSAGE IS NOT IN \"To receiver's alias: message\" FORMAT! PLEASE REDO!";
	 		String receiverAlias = senderAlias;
	 		ClientInfo receiver = mClients.get(receiverAlias); 
    	 		receiver.mClientSender.sendMessage(newMsg);
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
    	   			sendMessageToClients(message);
           }
        } catch (InterruptedException e) {
			System.err.print(e);
        }
    }
    
    
    public void checkCommand(ClientInfo aClientInfo) {
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
            System.err.println(":fail FAILED TO ESTABLISH SOCKET CONNECTION BETWEEN CHAT HUB AND " + senderIP + ":" + senderPort + "\n");
         }
    	
    		// ******************* PHASE 1 initial state ******************* //
		String receivedCipherSuite = null;
		while (receivedCipherSuite == null) {
			// ***** PHASE 1.1: receive :ka cipherSuite ***** //
			try {
				receivedCipherSuite = in.readUTF();
				System.out.println("PHASE 1.1 " + receivedCipherSuite);	
			} catch (IOException err) {
				System.err.println(":fail NO RESPONSE FROM CLIENT!");
			}
				
			// check whether received command equals to :ka
			String ka = Help.getCommand(receivedCipherSuite);
			try {
				Help.commandEqual(ka, ":ka");	
			} catch (ErrorException fail) {
				System.err.println(fail);
			}
			
			// check whether received cipher suite include server cipher suite
			String clientCipher = Help.getCipherSuite(receivedCipherSuite);
			try {
				Help.findCipherSuite(myCipherSuite, clientCipher);
			} catch (ErrorException fail) {
				System.err.println(fail);
			}
			
			finally {
				// ***** PHASE 1.2: send :kaok cipherSuite ***** //
				System.out.println("PHASE 1.2 :kaok "+ myCipherSuite);
				try {
					out.writeUTF(":kaok "+ myCipherSuite);
					out.flush();
				} catch (IOException ioe) {
			        System.err.println(":fail FAILED TO SEND :kaok CIPHERSUITE TO CLIENT!\n");
		        }
				
				// ***** PHASE 1.3: send :cert based64 encoded certificate *****//
				try {
					byte[] EncodedMyCert = Help.getCert(myKeyStore, myAlias);
					byte[] certEncodedMyCert = Help.addCommand(":cert ", EncodedMyCert);
					System.out.println("PHASE 1.3 :cert " + EncodedMyCert.toString());
					out.writeInt(certEncodedMyCert.length);
					out.write(certEncodedMyCert);
					out.flush();	
				} catch (IOException fail) {
					System.err.println(":fail FAILED TO SEND :cert ENCODED CERTIFICATE TO CLIENT!\n");
				}
				
				// ***** PHASE 1.3: send :ka1 based64 encoded public key *****//
				byte[] encodedPublic = myKey.getEncodedPublic();
				byte[] ka1encodedPublic = Help.addCommand(":ka1 ",encodedPublic);
				System.out.println("PHASE 1.3 :ka1 "+ encodedPublic.toString());	
				try {
					out.writeInt(ka1encodedPublic.length);
					out.write(ka1encodedPublic);
					out.flush();				
				} catch (IOException fail) {
					System.err.println(":fail FAILED TO SEND :ka1 ENCODED PUBLIC KEY TO CLIENT!\n");
				}
			}
		}		
    					
    		// ******************* PHASE 3: waiting for key agreement ******************* //
		int receiveSize = 0;
		while (receiveSize == 0) {
			// ***** PHASE 3.1: receive :cert server's encoded certificate ***** //
			byte[] certEncodedCert = null;
			try {
				receiveSize = in.readInt();
				certEncodedCert = new byte[receiveSize];
				in.readFully(certEncodedCert);
				System.out.println("PHASE 3.1 :cert " + certEncodedCert.toString());				
			} catch (IOException err) {
				System.err.println(":fail NO RESPONSE FROM SERVER!");
			}
			
			// ***** PHASE 3.1: verify :cert server's encoded certificate ***** //
			byte[] encodedCert = Help.splitCommand(":cert ", certEncodedCert);
			String clientAlias = Help.getAlias(myKeyStore, encodedCert, integrity);
			Help.certVerify(myKeyStore, clientAlias, encodedCert, integrity);
			System.out.println("PHASE 3.1 :cert " + encodedCert.toString() + " is verified (from " + clientAlias +")");
			aClientInfo.mAlias = clientAlias;
			
			// ***** PHASE 3.1: receive :ka1 client's encoded public key ***** //
			byte[] ka1clientPublic = null;
			try {
				receiveSize = in.readInt();
				ka1clientPublic = new byte[receiveSize];
				in.readFully(ka1clientPublic);
				System.out.println("PHASE 3.1 :ka1 " + ka1clientPublic.toString());
			} catch (IOException err) {
				System.err.println(":fail NO RESPONSE FROM CLIENT!");
			}
			
			// check whether received command equals to :ka1
			byte[] ka1 = Help.getCommand(":ka1 ", ka1clientPublic);
			try {
				Help.commandEqual(ka1, ":ka1 ");
			} catch (ErrorException fail) {
				System.err.println(fail);
			} finally {
				// ***** PHASE 3.2: generate shared secret ***** //
				myKey.doECDH(Help.splitCommand(":ka1 ", ka1clientPublic));
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
    public void makeMyKey() {
    		myKey = new KeyExchange(keyEstAlgor, keyEstSpec, integrity);
	}
    
    /**
     * initialize KeyExchange object myKey with given cipher suite and ClientInfo
     * 
     * @param the cipher suite sent by client, and ClientInformation
     */
    public void getMyKeyStore(String keystoreFileName, String password) {
		// initialize myAlias from the key store name (alias.jks)
		String[] temp = keystoreFileName.split("\\.");
		myAlias = temp[0];
		
		// initialize myKeyStore from the key store name
		keystoreFileName = System.getProperty("user.dir") + "/" + keystoreFileName;
		myKeyStore = Help.linkKeyStore(keystoreFileName, password);
    }
    
}