import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class A1 {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        {
            //Tag Generation
            String Key_in_Hex = "00112233445566778899AABBCCDDEEFF";
            String message = "You know my methods, Bob.";
            String idA = "3739298";
            String idB = "0070070";
            String Key = new BigInteger(Key_in_Hex, 16).toString();
            String tag_input = Key+message+idA+idB;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(tag_input.getBytes());
            byte[] original_tag =Arrays.copyOfRange(digest,28,32);
            System.out.println("-------------------------------------------");
            System.out.println("Original input and output: ");
            System.out.println("M: "+message);
            System.out.println("IDA = "+idA);
            System.out.println("MAC tag "+new BigInteger(original_tag));
            System.out.println("-------------------------------------------");

//            BigInteger alter= new BigInteger("-13984261");

            //Forgery
            SecureRandom random = new SecureRandom();
            long count = 0;
            byte[] input_random = new byte[400000000];
            byte[] key_bytes =Key.getBytes();
            byte[] id_bytes =(idA+idB).getBytes();
            ByteBuffer buf = ByteBuffer.allocate(key_bytes.length+id_bytes.length+4);
            boolean loop_signal = false;
            byte[] alternate_message = null;
            do{
                random.nextBytes(input_random);
                for(int i=0;i<400000000;i+=4) {
                    buf.put(key_bytes);
                    buf.put(Arrays.copyOfRange(input_random,i,i+4));
                    buf.put(id_bytes);
                    digest = md.digest(buf.array());
                    buf.clear();
                    count++;
                    if (Arrays.equals(original_tag,Arrays.copyOfRange(digest,28,32))) {
                        loop_signal=true;
                        alternate_message=Arrays.copyOfRange(input_random,i,i+4);
                        System.out.println("match="+count);
                        break;
                    }
                }
            } while(!loop_signal);

            buf.put(key_bytes);
            buf.put(alternate_message);
            buf.put(id_bytes);
            digest = md.digest(buf.array());
            byte[] Resulting_tag = Arrays.copyOfRange(digest,28,32);

            System.out.println("Forged input and output:");
            System.out.println("M': "+ new BigInteger(alternate_message));
            System.out.println("MAC tag1 "+new BigInteger(Resulting_tag));
            System.out.println("-------------------------------------------");

            //Verification
            System.out.println("Verification:");
            System.out.println("Verification result:"+Arrays.equals(original_tag,Resulting_tag));
            System.out.println("-------------------------------------------");

            System.out.println("Final Count:"+count);

        }
    }
}