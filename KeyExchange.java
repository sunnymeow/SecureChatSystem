import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.util.Arrays;
import java.util.Base64;


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
	public KeyExchange(String keyEstAlgor, String keyEstSpec, String integrity) throws Exception {
		this.keyEstAlgor = keyEstAlgor;
		this.keyEstSpec = keyEstSpec;
		this.integrity = integrity;
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		ECGenParameterSpec ecsp = new ECGenParameterSpec(keyEstSpec);
		
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
//	public String getEncodedPublic() {
//		return Base64.getEncoder().encodeToString(key_public.getEncoded());
//	}
	public byte[] getEncodedPublic() {
		return key_public.getEncoded();
	}
	
	
	/**
     * do the EDCH and construct shared secret
     * 
     * @param algorithm is the key agreement algorithm
     * @param othersPublicKey is the public key from the other side
     */
	public void doECDH(byte[] receivedPublicKey) throws Exception{
		// decoded public key
//		byte[] decodedKey = Base64.getDecoder().decode(receivedPublicKey);
//		PublicKey originalKey = (PublicKey) new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
	
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPublicKey);
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		System.out.println("Public key: " + pubKey.toString());
		
		// create a KeyAgreement object that implements the specified key agreement algorithm
		KeyAgreement ecdh = KeyAgreement.getInstance(keyEstAlgor);
		ecdh.init(key_private);
		ecdh.doPhase(pubKey, true);
		
		// generate secret key
		byte[] oriSecret = ecdh.generateSecret();
		System.out.println("Original secret key: " + oriSecret.toString());
		System.out.println("Original secret key: " + oriSecret.length);
		
		// only keep the last 16 byte of the secret key as final result
		
		key_secret = new byte[16];
	    for(int i = 0; i < 16; i++)
	        key_secret[i]=oriSecret[oriSecret.length-16+i];
		
		System.out.println("Final secret key: " + key_secret.toString());
		System.out.println("Final secret key: " + key_secret.length);
	}
	
	/**
     * get secret key 
     * 
     * @return the shared secret key 
     */
	public byte[] getSecret() {
		return key_secret;
	}

}
