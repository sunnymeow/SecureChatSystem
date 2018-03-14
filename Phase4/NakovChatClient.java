/**
 * Nakov Chat Client
 * (c) Svetlin Nakov, 2002
 *
 * NakovChatClient connects to Nakov Chat Server and prints all the messages
 * received from the server. It also allows the user to send messages to the
 * server. NakovChatClient thread reads messages and print them to the standard
 * output. 
 */
import java.io.*;
import java.net.*;
import java.security.KeyStore;

public class NakovChatClient {
    public static final String SERVER_HOSTNAME = "localhost";
    public static final int SERVER_PORT = 2004;
    private static Socket socket;
    private static BufferedReader mIn = null;
    private static PrintWriter mOut = null;
//    private static String myCipherSuite = "ecdh-secp224r1+X.509+AES_128/GCM/NoPadding//ecdh-secp256r1+x.509+AES_128/GCM/NoPadding";
    private static String myCipherSuite = "ecdh-secp224r1+X.509+AES/CBC/PKCS5Padding//ecdh-secp256r1+x.509+AES/CBC/PKCS5Padding";
	private static KeyExchange myKey;
	private static Encryption cov;
	private static String keyEstAlgor;	// key establish algorithm
	private static String keyEstSpec;	// specific parameter for key establish algorithm
	private static String integrity;		// a means for ensuring integrity of public key
	private static String symCipher;		// symmetric cipher
	private static KeyStore myKeyStore;
	private static String myAlias;

    public static void main(String[] args) {
    		
        // Connect to Nakov Chat Server
    		try {
           socket = new Socket(SERVER_HOSTNAME, SERVER_PORT);
           mIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		   mOut = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
           System.out.println("Connected to server " + SERVER_HOSTNAME + ":" + SERVER_PORT);
           
        } catch (IOException ioe) {
           System.err.println(":fail CAN'T ESTABLISH SOCKET CONNECTION TO " + SERVER_HOSTNAME + ":" + SERVER_PORT + "\n");
           System.exit(-1);
        }

    		// link client to key store
    		String ksFileName = args[0];
    		String password = args[1];
    		getMyKeyStore(ksFileName, password);
        
        // check command and key exchange
        checkCommand();

        // Create and start Sender thread
        Sender sender = new Sender(mOut, cov, myAlias);
        sender.setDaemon(true);
        sender.start();
        
        // Read messages from the server (socket) and print them
        try {
           String message = null;
           String ciphertext = null;
           while ((ciphertext=mIn.readLine()) != null) {        	   		
        	   		// decrypt input ciphertext
        	   		message = cov.decrypt(ciphertext);
			
				// display received message
				System.out.println(message);
				System.out.println("\t(Decrypted from cipher text: " + ciphertext + ")"); 
           }
        } catch (IOException ioe) {
        		System.err.println("DISCONNECTION FROM SERVER\n");
        		System.exit(-1);
        }
    }
    
    public static void checkCommand() {
    		DataInputStream in = null;
		DataOutputStream out = null;
		String senderIP = socket.getInetAddress().getHostAddress();
        String senderPort = "" + socket.getPort();
        
        // Connect to Nakov Chat Server
	    	try {
	    		in = new DataInputStream(socket.getInputStream());
	    		out = new DataOutputStream(socket.getOutputStream());
	    		System.out.println("******************* Start command check for " + senderIP + ":" + senderPort + " *******************");
	                       
	    	} catch (IOException ioe) {
	    		System.err.println(":fail CAN'T ESTABLISH STREAM CONNECTION TO " + SERVER_HOSTNAME + ":" + SERVER_PORT + "\n");
        }
    		
    	
    		// ******************* PHASE 1: send :ka cipherSuite ******************* //
		System.out.println("PHASE 1 :ka "+ myCipherSuite);
		try {
			out.writeUTF(":ka "+ myCipherSuite);
			out.flush();
		}	catch (IOException ioe) {
           System.err.println(":fail FAILED TO SEND :ka CIPHERSUITE TO SERVER!\n");
        }
		
		// ******************* PHASE 2: waiting for cipher suite confirmation ******************* //
		String receivedCipherSuite = null;
		while(receivedCipherSuite == null) {
			// ***** PHASE 2.1: receive :kaok ciphersuite ****** //
			try {
				receivedCipherSuite = in.readUTF();
				System.out.println("PHASE 2.1 " + receivedCipherSuite);
			} catch (IOException err) {
				System.err.println(":fail NO RESPONSE FROM SERVER!\n");
			}
			
			// check whether received command equals to :kaok
			try {
				String kaok = Help.getCommand(receivedCipherSuite);
				Help.commandEqual(kaok, ":kaok");	
			} catch (ErrorException fail) {
				System.err.println(fail);
			}
			finally {
				// use the received cipher suite to generate key
				makeMyKey(Help.getCipherSuite(receivedCipherSuite));
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
				System.err.println(":fail NO RESPONSE FROM SERVER!\n");
			}
			
			// ***** PHASE 3.1: verify :cert server's encoded certificate ***** //
			byte[] encodedCert = Help.splitCommand(":cert ", certEncodedCert);
			String serverAlias = Help.getAlias(myKeyStore, encodedCert, integrity);
			Help.certVerify(myKeyStore, serverAlias, encodedCert, integrity);
			System.out.println("PHASE 3.1 :cert " + encodedCert.toString() + " is verified (from " + serverAlias +")");
			
			// ***** PHASE 3.1: receive :ka1 server's encoded public key ***** //
			byte[] ka1serverPublic = null;
			try {
				receiveSize = in.readInt();
				ka1serverPublic = new byte[receiveSize];
				in.readFully(ka1serverPublic);
				System.out.println("PHASE 3.1 :ka1 " + ka1serverPublic.toString());				
			} catch (IOException err) {
				System.err.println(":fail NO RESPONSE FROM SERVER!\n");
			}
			
			// check whether received command equals to :ka1
			try {	
				byte[] ka1 = Help.getCommand(":ka1 ", ka1serverPublic);
				Help.commandEqual(ka1, ":ka1 ");                                               
			} catch (ErrorException fail) {
				System.err.println(fail);
			}
			
			finally {
				// ***** PHASE 2.2: send :cert based64 encoded certificate *****//
				byte[] EncodedMyCert = Help.getCert(myKeyStore, myAlias);
				byte[] certEncodedMyCert = Help.addCommand(":cert ", EncodedMyCert);
				System.out.println("PHASE 2.2 :cert " + EncodedMyCert.toString());
				try {
					out.writeInt(certEncodedMyCert.length);
					out.write(certEncodedMyCert);
					out.flush();	
				}	catch (IOException ioe) {
		           System.err.println(":fail FAILED TO SEND :cert ENCODED CERTIFICATED TO SERVER!\n");
		        }
				
				// ***** PHASE 2.2: send :ka1 based64 encoded public key ***** //
				byte[] encodedPublic = myKey.getEncodedPublic();
				byte[] ka1encodedPublic = Help.addCommand(":ka1 ", encodedPublic);
				System.out.println("PHASE 2.2 :ka1 "+ encodedPublic.toString());	
				try {
					out.writeInt(ka1encodedPublic.length);
					out.write(ka1encodedPublic);
					out.flush();
				} catch (IOException ioe) {
		           System.err.println(":fail FAILED TO SEND :ka1 ENCODED PUBLIC KEY TO SERVER!");
		        }

				// ***** PHASE 3.2: generate shared secret ***** //
				myKey.doECDH(Help.splitCommand(":ka1 ", ka1serverPublic));
				System.out.println("PHASE 3.2 share key: " + myKey.getSecret());
			}
		}		
		
		// ******************* PHASE 4: chat w/ msg encryption ******************* //
		// initialize Encryption object
		cov = new Encryption(myKey.getSecret(), symCipher);
		System.out.println("******************* Finish command check for " + senderIP + ":" + senderPort + " *******************");
		
    }
    
    /**
     * initialize KeyExchange object myKey with given cipher suite
     * 
     * @param the cipher suite sent by server
     */
	public static void makeMyKey(String receivedCipherSuite) {
		// separate cipher Suite tokens
		String[] trim1 = receivedCipherSuite.split("\\+");	// separate tokens
		String[] trim2 = trim1[0].split("\\-");				// separate algorithm and spec. parameters
				
		// get the individual element of cipher suite
		keyEstAlgor = trim2[0];
		keyEstSpec = trim2[1];
		integrity = trim1[1];
		symCipher = trim1[2];					
		
		// initialize KeyExchange object
		myKey = new KeyExchange(keyEstAlgor, keyEstSpec, integrity);
	}
	
	/**
     * initialize KeyExchange object myKey with given cipher suite and ClientInfo
     * 
     * @param the cipher suite sent by client, and ClientInformation
     */
    public static void getMyKeyStore(String keystoreFileName, String password) {
		// initialize myAlias from the key store name (alias.jks)
		String[] temp = keystoreFileName.split("\\.");
		myAlias = temp[0];
		
		// initialize myKeyStore from the key store name
		keystoreFileName = System.getProperty("user.dir") + "/" + keystoreFileName;
		myKeyStore = Help.linkKeyStore(keystoreFileName, password);
    }
}
