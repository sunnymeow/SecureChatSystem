import java.io.*;
import java.net.*;

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
	
		// strings to hold conversation contents
		String msgIn = "";
		String msgOut = "";
		String msgSecure = "";
		
		// initialize a secure conversation object
		Encryption cov = new Encryption();
		
		// terminate chat if server says "end"
		while(!msgOut.equals("bye")) {
			// read and decrypt client's message 
			msgIn = in.readUTF();
			msgSecure = cov.decrypt(msgIn);			
			System.out.print("Friend: ");
			System.out.println(msgSecure);
			
			// display the encrypted message from client before decryption
			System.out.println("(Decrypted from cipher text: " + msgIn + ")");			
			
			if (msgSecure.equals("bye")) {
				// terminate chat if client says "end"
				break;
			}
			else {
				// read keyboard input for server's message
				System.out.print("You: ");
				msgOut = buf.readLine();
				
				// encrypt and display server's encrypted message
				msgSecure = cov.encrypt(msgOut);
				System.out.println("(Encrypted into cipher text: " + msgSecure + ")");
				
				// sent the encrypted message to client
				out.writeUTF(msgSecure);
				out.flush();
			}
		}
	
		in.close();
		out.close();
		soc.close();
		System.out.println("\n************ Thanks for chatting! ************\n");
    }
}