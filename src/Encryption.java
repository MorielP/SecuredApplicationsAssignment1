/**import java.io.File;
import java.security.AlgorithmParameters;
import javax.crypto.*;
import java.security.*; //Provides Pseudo Random Number Generator (PRNG) functionality
import java.security.MessageDigest; //Provide the functionality of cryptographically secure message digest functions (e.g. SHA-256)


public class Encryption {
    File PlainText;
    File CipherText;
    String AlgorithmToUse;

    public byte[] ToByte(String plainText){
        byte[] PlainTextByteArray= plainText.getBytes();
        return  PlainTextByteArray;
    }

    public SecureRandom GetIV(int seed){
        SecureRandom secRandom = SecureRandom.getInstance("SHA1PRNG");
        secRandom.setSeed(20);
        byte[] bytes = new byte[20];
        secRandom.nextBytes(bytes);
        return secRandom;
    }

    public void GenerateSymetricKey(){

    }
}

public class Ciphering{
byte[] testdata = "Understanding Java Cryptography".getBytes();
Cipher myCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
myCipher.init(Cipher.ENCRYPT_MODE, sKey);
byte[] cipherText = myCipher.doFinal(testdata);**/

