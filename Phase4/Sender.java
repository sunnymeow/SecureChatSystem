/**
 * Nakov Chat Client
 * (c) Svetlin Nakov, 2002
 * 
 * Sender thread reads messages from the standard input and sends them
 * to the server.
 */
import java.io.*;

public class Sender extends Thread {
	private PrintWriter mOut;
	private Encryption cov;

	public Sender(PrintWriter aOut, Encryption aCov){
        mOut = aOut;
        cov = aCov;
	}

    /**
     * Until interrupted reads messages from the standard input (keyboard)
     * and sends them to the chat server through the socket.
     */
	public void run(){	
		String message = null;
		String ciphertext = null;
		try {
			Help.greeting();
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			while (!isInterrupted()) {
				message = in.readLine();
				try {
					ciphertext = cov.encrypt(message);
					System.out.println("(Encrypted into cipher text: " + ciphertext + ")");
				} catch (Exception err) {
					System.err.print(err);
					System.exit(-1);
				}
				mOut.println(ciphertext);
				mOut.flush();
				if (message.equals("exit")) {
					Help.ending();
        	   			break;
				}
			}
		} catch (IOException ioe) {
	            // Communication is broken
		}
	}
}
