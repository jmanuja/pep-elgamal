import java.math.*;
import java.util.*;
import java.security.*;
import java.io.*;
/**
 *
 * @author manuja
 */
public class PEP {

    /**
     * @param args the command line arguments
     */
     public static void main(String[] args) throws IOException
    {
        BigInteger p, b, c, secretKey;
        Random sc = new SecureRandom();
        secretKey = new BigInteger("1234567890");
        //
        // public key calculation
        //
        System.out.println("secretKey = " + secretKey);
        p = BigInteger.probablePrime(64, sc);
        b = new BigInteger("3545454");
        c = b.modPow(secretKey, p);
        System.out.println("p = " + p);
        System.out.println("b = " + b);
        System.out.println("c = " + c);
        //
        // Encryption
        //
        System.out.println("Enter your Big Number message -->");
        String s = "11111111";
        BigInteger X = new BigInteger(s);
        BigInteger r =new BigInteger("5555");// new BigInteger(64, sc);
        BigInteger EC = X.multiply(c.modPow(r, p)).mod(p);
        BigInteger brmodp = b.modPow(r, p);
        System.out.println("Plaintext = " + X);
        
        //
        // Decryption 1 
        // brmodp, secretKey, p, EC
        //
        decrypt(brmodp, secretKey, p, EC);
        
        
        //
        // Decryption 2 
        // brmodp2, secretKey2, p, EC2
        // This will change 
        // secretKey2 = secretKey x r2
        // r = r/r2       
        //
        BigInteger r2 =  new BigInteger("5558"); // this is random no. 
        BigInteger secretKey2 = r2.multiply(secretKey);
        BigInteger EC2 = X.multiply(c.modPow(r.divide(r2), p)).mod(p);
        BigInteger brmodp2 = b.modPow(r.divide(r2), p);

        decrypt(brmodp2, secretKey2, p.divide(r2), EC2);
        
        //
        // Decryption 3 
        // brmodp3, secretKey3, p, EC3
        // This will change 
        // secretKey3 = secretKey x r3
        // r = r/r3       
        //
        BigInteger r3 = new BigInteger("60000");
        BigInteger secretKey3 = r3.multiply(secretKey);
        BigInteger EC3 = X.multiply(c.modPow(r.divide(r3), p)).mod(p);
        BigInteger brmodp3 = b.modPow(r.divide(r3), p);

        decrypt(brmodp3, secretKey3, p, EC3);      
    }
     
    public static void decrypt(BigInteger brmodp,BigInteger secretKey,BigInteger p,BigInteger EC) {
        //
        // Decryption
        //
        BigInteger crmodp = brmodp.modPow(secretKey, p);
        BigInteger d = crmodp.modInverse(p);
        BigInteger ad = d.multiply(EC).mod(p);
        System.out.println("\n\nc^r mod p = " + crmodp);
        System.out.println("d = " + d);
        System.out.println("secretKey = " + secretKey);
        System.out.println("decodes: " + ad);
    }
     
}
