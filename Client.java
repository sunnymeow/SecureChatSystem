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
		Socket soc = new Socket("127.0.0.1", 4321);	
		
		// stream for getting input and output
		DataInputStream in = new DataInputStream(soc.getInputStream());
		DataOutputStream out = new DataOutputStream(soc.getOutputStream());
		
		// buffer to store message from keyboard input
		BufferedReader buf = new BufferedReader(new InputStreamReader(System.in));
		
		// strings to hold conversation contents
		String msgIn = "";
		String msgOut = "";
		String msgSecure = "";
		
		// initialize a secure conversation object
		Encryption cov = new Encryption();
    	
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