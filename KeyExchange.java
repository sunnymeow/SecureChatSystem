import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import java.util.Base64;


public class KeyExchange {
	private static PrivateKey key_private;
	private static PublicKey key_public;
	private static SecretKey key_secret;
	
	/**
     * Initialize the private key and public key  
     * 
     * @param key pair generator specified parameter
     */
	public KeyExchange(String ecgSpec) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		ECGenParameterSpec ecsp = new ECGenParameterSpec(ecgSpec);
		
		// Initializes the key pair generator using the specified parameter set 
	    kpg.initialize(ecsp);
	    
	    // save public key and private key
	    KeyPair key_pair = kpg.generateKeyPair();
	    key_private = key_pair.getPrivate();
	    key_public = key_pair.getPublic();
	    
	    // display key pair
	    System.out.println("\n******************* KeyExchange constructor *******************");
	    System.out.println("Private key: " + key_private.toString());
	    System.out.println("Public key: " + key_public.toString());
	    System.out.println("***************************************************************\n");
	}
	
	/**
     * base64 encode public key 
     * 
     * @return the base64 encoded string of public key 
     */
	public String getEncodedPublic() {
		return Base64.getEncoder().encodeToString(key_public.getEncoded());
	}
	
	/**
     * do the EDCH and construct shared secret
     * 
     * @param algorithm is the key agreement algorithm
     * @param othersPublicKey is the public key from the other side
     */
	public void doECDH(String algorithm, PublicKey othersPublicKey) throws Exception{
		// Returns a KeyAgreement object that implements the specified key agreement algorithm
		KeyAgreement ecdh = KeyAgreement.getInstance(algorithm);
		ecdh.init(key_private);
		ecdh.doPhase(othersPublicKey, true);
		
		key_secret = ecdh.generateSecret(algorithm);
		System.out.println("Secret key: " + key_secret.toString());
	}
	
	/**
     * get secret key 
     * 
     * @return the shared secret key 
     */
	public SecretKey getSecret() {
		return key_secret;
	}

	/**
     * get public key 
     * 
     * @return the uncoded public key 
     */
	public PublicKey getPublic() {
		return key_public;
	}
}
