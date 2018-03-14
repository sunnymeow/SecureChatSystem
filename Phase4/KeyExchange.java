import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;

public class KeyExchange {
	private static PrivateKey key_private;
	private static PublicKey key_public;
	private static byte[] key_secret;
	private String keyEstAlgor;		// key establish algorithm
	private String keyEstSpec;		// specific parameter for key establish algorithm
	private String integrity;		// a means for ensuring integrity of public key
	
	/**
     * Initialize the private key and public key  
     * 
     * @param key pair generator specified parameter
     */
	public KeyExchange(String keyEstAlgor, String keyEstSpec, String integrity) {
		this.keyEstAlgor = keyEstAlgor;
		this.keyEstSpec = keyEstSpec;
		this.integrity = integrity;
		
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
			ECGenParameterSpec ecsp = new ECGenParameterSpec(keyEstSpec);
			
			// Initializes the key pair generator using the specified parameter set 
		    kpg.initialize(ecsp);
		    
		    // save public key and private key
		    KeyPair key_pair = kpg.generateKeyPair();
		    key_private = key_pair.getPrivate();
		    key_public = key_pair.getPublic();
		    System.out.println("Public key: " + key_public.toString());
		} catch (Exception e) {
			System.err.println(":fail FAILED TO MAKE KEYEXCHANGE OBJECT\n");
		}
	}

	/**
     * do the EDCH and construct shared secret
     * 
     * @param algorithm is the key agreement algorithm
     * @param othersPublicKey is the public key from the other side
     */
	public void doECDH(byte[] receivedPublicKey) {
		try {
			// decoded public key
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPublicKey);
			PublicKey pubKey = keyFactory.generatePublic(keySpec);
			System.out.println("Received key: " + pubKey.toString());
			
			// create a KeyAgreement object that implements the specified key agreement algorithm
			KeyAgreement ecdh = KeyAgreement.getInstance(keyEstAlgor);
			ecdh.init(key_private);
			ecdh.doPhase(pubKey, true);
			 
			// generate secret key
			byte[] oriSecret = ecdh.generateSecret();
	
			// only keep the last 16 byte of the secret key as final result
			key_secret = new byte[16];
		    for(int i = 0; i < 16; i++) {
		        key_secret[i]=oriSecret[oriSecret.length-16+i];
		    }	
		} catch (Exception e) {
			System.err.println(":fail FAILED TO DO ECDH WITH RECEIVED PUBLIC KEY\n");
		}
	}
	
	/**
     * get the byte[] secret key 
     * 
     * @return the shared secret key 
     */
	public byte[] getSecret() {
		return key_secret;
	}
	
	/**
     * get byte[] base64 encode public key 
     * 
     * @return the base64 encoded string of public key 
     */
	public byte[] getEncodedPublic() {
		return key_public.getEncoded();
	}	
}
