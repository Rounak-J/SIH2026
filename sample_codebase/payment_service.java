import java.security.*;

public class PaymentService {
    public void signTransaction() throws Exception {
        // ECDSA is vulnerable to Shor's algorithm
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair pair = keyGen.generateKeyPair();
        
        // SHA-1 is deprecated
        Signature ecdsaSign = Signature.getInstance("SHA1withECDSA");
        ecdsaSign.initSign(pair.getPrivate());
    }
}
