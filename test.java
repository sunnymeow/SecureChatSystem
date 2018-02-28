import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;

public class test {
  public static void main(String[] args) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec ecsp = new ECGenParameterSpec("secp224r1");
    kpg.initialize(ecsp);

    KeyPair Alice = kpg.genKeyPair();
    PrivateKey Alice_private = Alice.getPrivate();
    PublicKey Alice_public = Alice.getPublic();
    System.out.println("Alice's private key: " + Alice_private.toString());
    System.out.println("Alice's public key: " + Alice_public.toString());

    KeyPair Bob = kpg.genKeyPair();
    PrivateKey Bob_private = Bob.getPrivate();
    PublicKey Bob_public = Bob.getPublic();
    System.out.println("Bob's private key: " + Bob_private.toString());
    System.out.println("Bob's public key: " + Bob_public.toString());

    KeyAgreement ecdhU = KeyAgreement.getInstance("ecdh");
    ecdhU.init(Alice_private);
    ecdhU.doPhase(Bob_public,true);

    KeyAgreement ecdhV = KeyAgreement.getInstance("ecdh");
    ecdhV.init(Bob_private);
    ecdhV.doPhase(Alice_public,true);

    System.out.println("Secret computed by Alice: 0x" + 
                       (new BigInteger(1, ecdhU.generateSecret()).toString(16)).toUpperCase());
    System.out.println("Secret computed by Bob  : 0x" + 
                       (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());
  }
}