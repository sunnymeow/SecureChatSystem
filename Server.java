import java.io.*;
import java.net.*;
import java.util.concurrent.TimeUnit;

public class Server  {
	public static void main (String args[]) throws Exception {
		// greetings
		System.out.println("************** Welcome to the Chat Hub! **************");
		System.out.println("*  - Your friend is starting a chat with you         *");
		System.out.println("*  - Please wait for your friend's first message     *");
		System.out.println("*  - When finish, enter \"bye\" to exit the chat       *");
		System.out.println("******************************************************");
		
		// socket link to the server socket with its port number
		ServerSocket serSoc = new ServerSocket(4321);
		Socket soc = serSoc.accept();
			
		// stream for getting input and output
		DataInputStream in = new DataInputStream(soc.getInputStream());
		DataOutputStream out = new DataOutputStream(soc.getOutputStream());
		
		// buffer to store message from keyboard input
		BufferedReader buf = new BufferedReader(new InputStreamReader(System.in));
	
		
		// ******************* PHASE 1.1: receive :ka cipherSuite ******************* //
		String cipherSuite = "";
		String keyEstAlgor = "";		// key establish algorithm
		String keyEstSpec = "";		// specific parameter for key establish algorithm
		String integrity = "";		// a means for ensuring integrity of public key
		String symCipher = "";		// symmetric cipher
				
		cipherSuite = in.readUTF();
		System.out.println("PHASE 1.1 " + cipherSuite);
		TimeUnit.SECONDS.sleep(3);
		
		// ******************* PHASE 1.2: send :kaok cipherSuite ******************* //
		cipherSuite = "ecdh-secp224r1+nocert+aes128/cbc";
		System.out.println("PHASE 1.2 :kaok "+ cipherSuite);
		out.writeUTF(":kaok "+ cipherSuite);
		out.flush();
		TimeUnit.SECONDS.sleep(3);
				
		// separate tokens
		String[] trim2 = cipherSuite.split("\\+");		// separate tokens
		String[] trim3 = trim2[0].split("\\-");			// separate algorithm and spec. parameters
				
		// get the cipher suite
		keyEstAlgor = trim3[0];
		keyEstSpec = trim3[1];
		integrity = trim2[1];
		symCipher = trim2[2];

		// ******************* PHASE 1.3: send :ka1 based64 encoded public key ******************* //
		KeyExchange myKey = new KeyExchange(keyEstSpec);
		System.out.println("PHASE 2.2 encoded "+ myKey.getEncodedPublic().toString());
		System.out.println("PHASE 2.2 :ka1 "+ myKey.getPublic().toString());
		out.writeUTF(":ka1 "+ myKey.getPublic().toString());
		TimeUnit.SECONDS.sleep(3);
		
		// ******************* PHASE 3.1: receive :ka1 client's encoded public key ******************* //
		String clientPublic = in.readUTF();
		System.out.println("PHASE 3.1 " + clientPublic);
		TimeUnit.SECONDS.sleep(3);
		
		
//		// ******************* PHASE 4: chat w/ msg encryption ******************* //	
//		// strings to hold conversation contents
//		String msgIn = "";
//		String msgOut = "";
//		String msgSecure = "";
//				
//		// initialize a secure conversation object
//		Encryption cov = new Encryption();
//		
//		// terminate chat if server says "end"
//		while(!msgOut.equals("bye")) {
//			// read and decrypt client's message 
//			msgIn = in.readUTF();
//			msgSecure = cov.decrypt(msgIn);			
//			System.out.print("Friend: ");
//			System.out.println(msgSecure);
//			
//			// display the encrypted message from client before decryption
//			System.out.println("(Decrypted from cipher text: " + msgIn + ")");			
//			
//			if (msgSecure.equals("bye")) {
//				// terminate chat if client says "end"
//				break;
//			}
//			else {
//				// read keyboard input for server's message
//				System.out.print("You: ");
//				msgOut = buf.readLine();
//				
//				// encrypt and display server's encrypted message
//				msgSecure = cov.encrypt(msgOut);
//				System.out.println("(Encrypted into cipher text: " + msgSecure + ")");
//				
//				// sent the encrypted message to client
//				out.writeUTF(msgSecure);
//				out.flush();
//			}
//		}
//	
//		in.close();
//		out.close();
//		soc.close();
//		System.out.println("\n************ Thanks for chatting! ************\n");
    }
}