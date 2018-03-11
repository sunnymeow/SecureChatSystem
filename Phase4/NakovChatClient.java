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

public class NakovChatClient {
    public static final String SERVER_HOSTNAME = "localhost";
    public static final int SERVER_PORT = 2004;
    private static Socket socket;
    private static BufferedReader mIn = null;
    private static PrintWriter mOut = null;
    private static String myCipherSuite = "ecdh-secp224r1+nocert+AES/CBC/PKCS5Padding//ecdh-secp256r1+x509+aes128/gcm128";
	private static KeyExchange myKey;
	private static Encryption cov;
	private static String keyEstAlgor;	// key establish algorithm
	private static String keyEstSpec;	// specific parameter for key establish algorithm
	private static String integrity;		// a means for ensuring integrity of public key
	private static String symCipher;		// symmetric cipher

    public static void main(String[] args) throws Exception{
    		
        try {
           // Connect to Nakov Chat Server
           socket = new Socket(SERVER_HOSTNAME, SERVER_PORT);
           System.out.println("Connected to server " + SERVER_HOSTNAME + ":" + SERVER_PORT);
           
        } catch (IOException ioe) {
           System.err.println("Can not establish connection to " + SERVER_HOSTNAME + ":" + SERVER_PORT);
           ioe.printStackTrace();
           System.exit(-1);
        }

       // check command and key exchange
       checkCommand();
       
       try {
           // Connect to Nakov Chat Server
           mIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
           mOut = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));           
                      
        } catch (IOException ioe) {
           System.err.println("Can not establish connection to " + SERVER_HOSTNAME + ":" + SERVER_PORT);
           ioe.printStackTrace();
           System.exit(-1);
        }
        
        // Create and start Sender thread
        Sender sender = new Sender(mOut, cov);
        sender.setDaemon(true);
        sender.start();
        
        try {
           // Read messages from the server (socket) and print them
           String message = null;
           String ciphertext = null;
           while ((ciphertext=mIn.readLine()) != null) {        	   		
	        	   try {
	        		   message = cov.decrypt(ciphertext);
				} catch (ErrorException err) {
					System.err.print(err);
					System.exit(-1);
				}
				finally {
					// display received message
					System.out.println(message);
					// display the encrypted message from server before decryption
					System.out.println("(Decrypted from cipher text: " + ciphertext + ")");
				}     
           }
        } catch (IOException ioe) {
           System.err.println("Connection to server broken.");
           ioe.printStackTrace();
        }
    }
    
    public static void checkCommand() throws Exception{
    		DataInputStream in = null;
		DataOutputStream out = null;
		String senderIP = socket.getInetAddress().getHostAddress();
        String senderPort = "" + socket.getPort();
        
	    	try {
	        // Connect to Nakov Chat Server
	    		in = new DataInputStream(socket.getInputStream());
	    		out = new DataOutputStream(socket.getOutputStream());
	    		System.out.println("******************* Start command check for " + senderIP + ":" + senderPort + " *******************");
	                       
	    } catch (IOException ioe) {
	    		System.err.println("Can not establish connection to " + SERVER_HOSTNAME + ":" + SERVER_PORT);
            ioe.printStackTrace();
            System.exit(-1);
         }
    		
    	
    		// ******************* PHASE 1: send :ka cipherSuite ******************* //
		System.out.println("PHASE 1 :ka "+ myCipherSuite);
		out.writeUTF(":ka "+ myCipherSuite);
		out.flush();
		
		// ******************* PHASE 2: waiting for cipher suite confirmation ******************* //
		String receivedCipherSuite = null;
		while(receivedCipherSuite == null) {
			// ***** PHASE 2.1: receive :kaok ciphersuite ****** //
			try {
				receivedCipherSuite = in.readUTF();
				System.out.println("PHASE 2.1 " + receivedCipherSuite);
			} catch (Exception err) {
				System.err.println("NO RESPONSE FROM SERVER!");
				System.exit(-1);
			}
			
			// check whether received command equals to :kaok
			try {
				String kaok = Help.getCommand(receivedCipherSuite);
				Help.commandEqual(kaok, ":kaok");	
			} catch (ErrorException fail) {
				System.err.print(fail);
				System.exit(-1);
			}
			finally {
				// use the received cipher suite to generate key
				makeMyKey(Help.getCipherSuite(receivedCipherSuite));
			}
		}
		
		// ******************* PHASE 3: waiting for key agreement ******************* //
		int receiveSize = 0;
		while (receiveSize == 0) {
			// ***** PHASE 3.1: receive :ka1 server's encoded public key ***** //
			byte[] ka1serverPublic = null;
			try {
				receiveSize = in.readInt();
				ka1serverPublic = new byte[receiveSize];
				in.readFully(ka1serverPublic);
				System.out.println("PHASE 3.1 :ka1 " + ka1serverPublic.toString());				
			} catch (Exception err) {
				System.err.println("NO RESPONSE FROM SERVER!");
				System.exit(-1);
			}
			
			// check whether received command equals to :ka1
			try {	
				byte[] ka1 = Help.getKa1(ka1serverPublic);
				Help.commandEqual(ka1, ":ka1 ");
			} catch (ErrorException fail) {
				System.err.print(fail);
				System.exit(-1);
			}
			
			finally {
				// ***** PHASE 2.2: send :ka1 based64 encoded public key ***** //
				byte[] encodedPublic = myKey.getEncodedPublic();
				byte[] ka1encodedPublic = Help.addKa1(encodedPublic);
				System.out.println("PHASE 2.2 :ka1 "+ encodedPublic.toString());		
				out.writeInt(ka1encodedPublic.length);
				out.write(ka1encodedPublic);
				out.flush();

				// ***** PHASE 3.2: generate shared secret ***** //
				myKey.doECDH(Help.splitEncodedPublic(ka1serverPublic));
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
	public static void makeMyKey(String receivedCipherSuite) throws Exception {
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
}
