import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class A2 {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        {
            // Key Generation
            BigInteger P = new BigInteger("5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807");
            BigInteger G = new BigInteger("2");
            BigInteger X,Y;
            SecureRandom random = new SecureRandom();
            do {
                X = BigInteger.valueOf(random.nextLong());
            }while( X.longValue()<=1 || P.subtract(BigInteger.valueOf(1)).compareTo(X)==-1);
            Y=G.modPow(X,P);
            System.out.println("-------------------------------------------");
            System.out.println("Key Generation:");
            System.out.println("ElGamal signing key x = "+X);
            System.out.println("ElGamal verification key vk = (y, g, p) = ("+Y+", "+G+", "+P+")");
            System.out.println("-------------------------------------------");

            //Signing
            String message_String ="12345";
            byte[] messgae_byte_array = message_String.getBytes();
            BigInteger K,R,KInv,S;
            do {
                K = BigInteger.valueOf(random.nextLong());
            }while((K.gcd(P.subtract(BigInteger.valueOf(1))).longValue())!=1 ||  K.longValue()<=1 || P.subtract(BigInteger.valueOf(2)).compareTo(X)==-1);
            R = G.modPow(K,P);
            KInv = K.modInverse(P.subtract(BigInteger.valueOf(1)));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] SHA256 = md.digest(messgae_byte_array);
            BigInteger SHA256_BigInteger = new BigInteger(SHA256);
            S = KInv.multiply(SHA256_BigInteger.subtract(X.multiply(R))).mod(P.subtract(BigInteger.valueOf(1)));
            System.out.println("Signing:");
            System.out.println("Message to be signed m = "+X);
            System.out.println("Signature = (r, s) = ("+R+", "+S+")");
            System.out.println("-------------------------------------------");

            //Verify
            BigInteger U = Y.modPow(R,P).multiply(R.modPow(S,P)).mod(P);
            BigInteger V = G.modPow(SHA256_BigInteger,P);
            System.out.println("Verification:");
            System.out.println("Printing u = "+U);
            System.out.println("Printing h = "+SHA256_BigInteger);
            System.out.println("Printing v = "+V);
            if(U.compareTo(V)==0) {
                System.out.println("Verification result: Yes ");
            }else {
                System.out.println("Verification result: No ");
            }
        }
    }
}