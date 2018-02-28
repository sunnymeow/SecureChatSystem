import java.io.*;
import java.net.*;

public class Client {
    public static void main (String args[]) throws Exception {
    		// greetings
    		System.out.println("************** Welcome to the Chat Hub! **************");
    		System.out.println("*  - You're now starting a chat with your friend     *");
    		System.out.println("*  - Please enter the first message to your friend   *");
    		System.out.println("*  - When finish, enter \"bye\" to exit the chat       *");
    		System.out.println("******************************************************");

    		// socket connect to server with server's IP (local) and port number
		Socket soc = new Socket("127.0.0.1", 1234);	
		
		// stream for getting input and output
		DataInputStream in = new DataInputStream(soc.getInputStream());
		DataOutputStream out = new DataOutputStream(soc.getOutputStream());

		// buffer to store message from keyboard input
		BufferedReader buf = new BufferedReader(new InputStreamReader(System.in));
		
		// ******************* PHASE 1: send :ka cipherSuite ******************* //
		String cipherSuite = "ecdh-secp224r1+nocert+aes128/cbc";					//////// hardcoding 
		String keyEstAlgor = "";		// key establish algorithm
		String keyEstSpec = "";		// specific parameter for key establish algorithm
		String integrity = "";		// a means for ensuring integrity of public key
		String symCipher = "";		// symmetric cipher
		
		System.out.println("PHASE 1 :ka "+ cipherSuite);
		out.writeUTF(":ka "+ cipherSuite);
		out.flush();
		
		// ******************* PHASE 2.1: receive :kaok ciphersuite ******************* //
		cipherSuite = "";
		cipherSuite = in.readUTF();
		System.out.println("PHASE 2.1 " + cipherSuite);
		
		// separate tokens
		String[] trim1 = cipherSuite.split(" ");			// trim off :kaok
		String[] trim2 = trim1[1].split("\\+");			// separate tokens
		String[] trim3 = trim2[0].split("\\-");			// separate algorithm and spec. parameter
		
		// get the cipher suite
		keyEstAlgor = trim3[0];
		keyEstSpec = trim3[1];
		integrity = trim2[1];
		symCipher = trim2[2];
		
		// ******************* PHASE 3.1: receive :ka1 server's encoded public key ******************* //
		byte[] serverPublic = new byte[in.readInt()];
		in.readFully(serverPublic);
		System.out.println("PHASE 3.1 :ka1 " + serverPublic.toString());			//////// hardcoding :ka1
		
		// ******************* PHASE 2.2: send :ka1 based64 encoded public key ******************* //
		KeyExchange myKey = new KeyExchange(keyEstAlgor, keyEstSpec, integrity);
		System.out.println("PHASE 2.2 :ka1 "+ myKey.getEncodedPublic().toString());		//////// hardcoding :ka1
		out.writeInt(myKey.getEncodedPublic().length);
		out.write(myKey.getEncodedPublic());
		out.flush();
		
		// ******************* PHASE 3.2: generate shared secret ******************* //
		myKey.doECDH(serverPublic);
		
		// ******************* PHASE 4: chat w/ msg encryption ******************* //
		// strings to hold conversation contents
		String msgIn = "";
		String msgOut = "";
		String msgSecure = "";
		
		// initialize a secure conversation object
		Encryption cov = new Encryption(myKey.getSecret(), symCipher);
    	
		// terminate chat if server says "end"
		while(!msgSecure.equals("bye")) {
			// read keyboard input for client's message
			System.out.print("You: ");
			msgOut = buf.readLine();
			
			// encrypt and display client's encrypted message
			msgSecure = cov.encrypt(msgOut);
			System.out.println("(Encrypted into cipher text: " + msgSecure + ")");
			
			// sent the encrypted message to server
			out.writeUTF(msgSecure);
			out.flush();
			
			if (msgOut.equals("bye")) {
				// terminate chat if client says "end"
				break;
			}
			else {
				// read and decrypt server's message 
				msgIn = in.readUTF();
				msgSecure = cov.decrypt(msgIn);
				System.out.print("Friend: ");
				System.out.println(msgSecure);
				
				// display the encrypted message from server before decryption
				System.out.println("(Decrypted from cipher text: " + msgIn + ")");
			}
			
		}
		in.close();
		out.close();
		soc.close();
		
		System.out.println("\n************ Thanks for chatting! ************\n");
    }
}