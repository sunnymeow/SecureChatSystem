/**
 * Nakov Chat Server
 * (c) Svetlin Nakov, 2002
 *
 * ClientInfo class contains information about a client, connected to the server.
 */
import java.net.Socket;

public class ClientInfo {
    public Socket mSocket = null;
    public ClientListener mClientListener = null;
    public ClientSender mClientSender = null;
	public Encryption mEncrption = null;

}