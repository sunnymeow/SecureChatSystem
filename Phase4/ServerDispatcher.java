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
	private final static String myCipherSuite = "ecdh-secp224r1+X.509+AES_128/GCM/NoPadding";
	private final static String keyEstAlgor = "ecdh";		// key establish algorithm
	private final static String keyEstSpec = "secp224r1";	// specific parameter for key establish algorithm
	private final static String integrity = "X.509";		// a means for ensuring integrity of public key
	private final static String symCipher="AES/CBC/PKCS5Padding";		// symmetric cipher
	private KeyExchange myKey;
	private KeyStore myKeyStore;
	private String myAlias;
	
    private static HashMap<String, ClientInfo> mMessageQueue = new HashMap<String, ClientInfo>(); 	// Hashmap <receiver alias, message>
    private static HashMap<String, ClientInfo> mClients = new HashMap<String, ClientInfo>();		// Hashmap <alias, ClientInfo>
    
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
    public synchronized void deleteClient(ClientInfo aClientInfo) throws IOException {
    		mClients.remove(aClientInfo.mAlias);
    }

    /**
     * Adds given message to the message queue and notifies this thread
     * (actually getNextMessageFromQueue method) that a message is arrived.
     * sendMessage is called by other threads (ServeDispatcher).
     */
    public synchronized void dispatchMessage(ClientInfo aClientInfo, String aMessage)   {
    		mMessageQueue.put(aMessage, aClientInfo);
    		notify();
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
    private synchronized void sendMessageToClients() throws ErrorException, InterruptedException {  
    		while (mMessageQueue.isEmpty())
    			wait();
		try {
			Iterator<Map.Entry<String, ClientInfo>> iterator = mMessageQueue.entrySet().iterator();
	    	     Map.Entry<String, ClientInfo> entry = iterator.next();
	    	     String message = entry.getKey(); 
	    	     ClientInfo sender = entry.getValue();
	    	     String newMsg = null;
	    	     String receiverAlias = null;
	    	     ClientInfo receiver = null;
	    	     
	    	     if (message.contains(":")) {
		    	     // extract receiver from message
		    	     String[] split = message.split("\\:");
		    	     String toRec = split[0];
		    	     receiverAlias = toRec.split(" ")[1];
		    	     
		    	     // modify the message from sender format to receiver format
		    	     newMsg = "From " + sender.mAlias + " : " + split[1];
		    	     
		    	     if (receiverAlias.toLowerCase().equals("all")) {
		    	    	 	sendMessageToAllClients(newMsg);
		    	     } 
		    	     else {
		    	    	 	if (mClients.get(receiverAlias)==null) {
		    	    	 		newMsg = ":err CAN'T FIND CLIENT ALIAS NAME IN CHAT HUB CLIENT LIST! PLEASE REDO!";
		    	    	 		receiver = sender;
		    	    	 	}
		    	    	 	else {
		    	    	 		receiver = mClients.get(receiverAlias); 
		    	    	 	} 
		    	      }
		    	   }
		    	   else {
		    		   	newMsg = ":err PLEASE FOLLOW THE FORMAT \"To receiver's alias: message\" AND REDO!";
		    	    	 	receiver = sender;
		    	     }
    	    	 	// send the modified message to specific receiver
    	    	 	receiver.mClientSender.sendMessage(newMsg);
	    	     // remove the sent message
	    	     mMessageQueue.remove(message);
		} catch (Exception e) {
			throw new ErrorException(":err FAILED TO GET MESSAGE FROM SERVER QUEUE AND SEND TO CLIENT!\n");
		}    		
    }
    
    
    /**
     * Infinitely reads messages from the queue and dispatch them
     * to all clients connected to the server.
     */
    public void run()  {
        try {
           while (true) {
    	   		try {
    	   			sendMessageToClients();
    	   		} catch (ErrorException fail) {
				System.err.print(fail);
				System.exit(-1);
    	   		}
           }
        } catch (Exception e) {
			System.err.print(e);
			System.exit(-1);
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
            System.err.println(":fail FAILED TO ESTABLISH SOCKET CONNECTION BETWEEN CHAT HUB AND " + senderIP + ":" + senderPort);
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
				System.err.println(":fail NO RESPONSE FROM CLIENT!");
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
				
				// ***** PHASE 1.3: send :cert based64 encoded certificate *****//
				try {
					byte[] EncodedMyCert = Help.getCert(myKeyStore, myAlias);
					byte[] certEncodedMyCert = Help.addCommand(":cert ", EncodedMyCert);
					System.out.println("PHASE 1.3 :cert " + EncodedMyCert.toString());
					out.writeInt(certEncodedMyCert.length);
					out.write(certEncodedMyCert);
					out.flush();	
				} catch (ErrorException fail) {
					System.err.print(fail);
					System.exit(-1);
				}
				
				// ***** PHASE 1.3: send :ka1 based64 encoded public key *****//
				byte[] encodedPublic = myKey.getEncodedPublic();
				byte[] ka1encodedPublic = Help.addCommand(":ka1 ",encodedPublic);
				System.out.println("PHASE 1.3 :ka1 "+ encodedPublic.toString());	
				out.writeInt(ka1encodedPublic.length);
				out.write(ka1encodedPublic);
				out.flush();				
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
			} catch (Exception err) {
				System.err.println(":fail NO RESPONSE FROM SERVER!");
				System.exit(-1);
			}
			
			// ***** PHASE 3.1: verify :cert server's encoded certificate ***** //
			try {
				byte[] encodedCert = Help.splitCommand(":cert ", certEncodedCert);
				String clientAlias = Help.getAlias(myKeyStore, encodedCert, integrity);
				Help.certVerify(myKeyStore, clientAlias, encodedCert, integrity);
				System.out.println("PHASE 3.1 :cert " + encodedCert.toString() + " is verified (from " + clientAlias +")");
				aClientInfo.mAlias = clientAlias;
			} catch (ErrorException fail) {
				System.err.print(fail);
				System.exit(-1);
			}
			
			// ***** PHASE 3.1: receive :ka1 client's encoded public key ***** //
			try {
				receiveSize = in.readInt();
			} catch (Exception err) {
				System.err.println(":fail NO RESPONSE FROM CLIENT!");
				System.exit(-1);
			}
			byte[] ka1clientPublic = new byte[receiveSize];
			in.readFully(ka1clientPublic);
			System.out.println("PHASE 3.1 :ka1 " + ka1clientPublic.toString());
			
			// check whether received command equals to :ka1
			byte[] ka1 = Help.getCommand(":ka1 ", ka1clientPublic);
			try {
				Help.commandEqual(ka1, ":ka1 ");
			} catch (ErrorException fail) {
				System.err.print(fail);
				System.exit(-1);
			}
			
			finally {
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
    public void makeMyKey() throws Exception {
    		try {
    			myKey = new KeyExchange(keyEstAlgor, keyEstSpec, integrity);
    		} catch (Exception e) {
    			throw new ErrorException(":fail FAILED TO MAKE KEYEXCHANGE OBJECT\n");
    		}
	}
    
    /**
     * initialize KeyExchange object myKey with given cipher suite and ClientInfo
     * 
     * @param the cipher suite sent by client, and ClientInformation
     */
    public void getMyKeyStore(String keystoreFileName, String password) throws ErrorException {
		// initialize myAlias from the key store name (alias.jks)
    		try {
    			String[] temp = keystoreFileName.split("\\.");
    			myAlias = temp[0];
    			
    			// initialize myKeyStore from the key store name
    			keystoreFileName = System.getProperty("user.dir") + "/" + keystoreFileName;
    			myKeyStore = Help.linkKeyStore(keystoreFileName, password);
    		} catch (Exception e) {
    			throw new ErrorException(":fail KEYSTORE " + keystoreFileName + " FAILED TO LINK TO CHAT HUB SOCKET!\n");
    		}
    }
    
}