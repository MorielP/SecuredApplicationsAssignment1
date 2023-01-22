package crypto;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.cert.Certificate;
import java.util.Base64;
import java.nio.file.*;
import java.util.concurrent.*;

public class Crypto {
    static String usage = "crypto CONF INPUT_DATA";

    //Get the private and public keys from the certificate with alias "alias" (given in conf file)
    static KeyPair getKeyPair(X509Certificate cert, KeyStore keyStore, String alias, String password) throws Exception{
        Key key = keyStore.getKey(alias, password.toCharArray());
        PublicKey publicKey = cert.getPublicKey();

        if (key==null){
            System.out.println("keyStore.getKey didnt work");
        }
        return new KeyPair(publicKey, (PrivateKey)key);
    }

    //Get the keystore given in the conf file
    static KeyStore getKeyStore(String path, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(path);
        keyStore.load(fis, password.toCharArray());
        return keyStore;
    }

    // Verify the signature given in the conf file, using the public key and the signature algorithm provided by the user
    private static boolean verifySignature(KeyPair kp, byte[] data, byte[] signature, String algorithm) throws Exception {
        Signature sig = Signature.getInstance(algorithm);
        try {
            sig.initVerify(kp.getPublic());
            sig.update(data);
            return sig.verify(signature);
        } catch (InvalidKeyException e) {
            System.out.println("Verify signature: invalid key");
            return false;
        } catch (SignatureException e) {
            System.out.println("Verify signature: signature exception");
            return false;
        }
    }

    // Sign the data
     static byte[] sign(Conf conf, KeyPair kp, byte[] data, String algorithm) throws Exception {
        Signature sig;
        try {
            Signature sig1=Signature.getInstance(algorithm,conf.prop.getProperty("signatureProvider"));
            sig = sig1;
        } catch (Exception e ){
            Signature sig1 = Signature.getInstance(algorithm);
            sig =sig1;
        }

        sig.initSign(kp.getPrivate());
        sig.update(data);
        return sig.sign();
    }

    //Decrypt the cipherText created by encryption, using the same algorithm, IV, and the symmetric key of the public key used for encryption
    private static byte[] decryptData(String inputFile, Conf conf, SecretKey symmetricKey, byte[] data, IvParameterSpec IV) throws Exception {
        String cipherProvider = conf.prop.getProperty("cipherProvider");
        Cipher enc = Cipher.getInstance(conf.prop.getProperty("cipherTpEncryptData"),cipherProvider);
        try {
            enc.init(Cipher.DECRYPT_MODE, symmetricKey, IV);
        } catch (Exception e){
            conf.store(inputFile+ ".plain", "Bad decryption:", "File didn't pass integrity test");
        }
        return enc.doFinal(data);
    }

    //Encrypt the plainText provided by the user, using the automatically-generated symmetric key and IV, and the user-provided algorithm and provider (if applies)
    private static byte[] encryptData(Conf conf, SecretKey symmetricKey, byte[] data, IvParameterSpec IV) throws Exception {
        String cipherProvider = conf.prop.getProperty("cipherProvider");
        Cipher enc = Cipher.getInstance(conf.prop.getProperty("cipherTpEncryptData"), cipherProvider);
        enc.init(Cipher.ENCRYPT_MODE, symmetricKey, IV);
        return enc.doFinal(data);
    }

    //Read the input data (plaintext when encrypting, cipherText when decrypting) into a byte array
    public static byte[] readFile(String path) throws Exception {
        InputStream in = new FileInputStream(path);
        long fileSize = new File(path).length();
        byte[] data = new byte[(int) fileSize];
        in.read(data);
        return data;
    }

    //Write output
    public static void writeFile(String path, byte[] data) throws Exception {
        OutputStream outputStream = new FileOutputStream(path);
        outputStream.write(data);
    }

    //Initialize all vars needed for encryption,
    public static byte[] encrypt(X509Certificate cert, KeyPair kp, Conf conf, String confPath,  String inputFile, String algorithm, int keyLength) throws Exception {
        byte[] plainData = readFile(inputFile);
        IvParameterSpec IV = generateIV(conf, confPath);
        SecretKey symmetricKey = generateSymmetricKey(cert, conf, confPath, keyLength);
        byte[] encryptedData = encryptData(conf, symmetricKey, plainData, IV);
        byte[] signature = sign(conf, kp, encryptedData, algorithm);
        writeFile("encrypted.txt", encryptedData);
        return signature;
    }

    //Generate a 128bit IV and write it to conf file for decryption
    public static IvParameterSpec generateIV(Conf conf, String confPath) throws Exception{
        SecureRandom secRandom = SecureRandom.getInstance("SHA1PRNG");
        secRandom.setSeed(711);
        byte[] bytes = new byte[16];
        secRandom.nextBytes(bytes);
        IvParameterSpec IV = new IvParameterSpec(bytes);
        String IVString = Base64.getEncoder().encodeToString(bytes);
        conf.store(confPath + ".decryptor", "IVString" ,IVString);
        return IV;
    }

    // Generate symmetric key for the plaintext encryption
    public static SecretKey generateSymmetricKey(X509Certificate cert, Conf conf, String confPath, int keyLength) throws Exception{
        KeyGenerator symmetricKeyGenerator = KeyGenerator.getInstance("AES");
        symmetricKeyGenerator.init(keyLength);
        SecretKey symmetricKey = symmetricKeyGenerator.generateKey();
        EncryptSymmetricKey(conf, confPath, cert, symmetricKey);
        return symmetricKey;
    }

    //Encrypt the symmetric key and save it in the conf file for future decryption
    public static void EncryptSymmetricKey(Conf conf,String confPath, Certificate cert, SecretKey symmetricKey) throws  Exception{
        PublicKey keyToEncryptSymmetricKey = cert.getPublicKey();
        Cipher cipherToEncryptSymmetricKey = Cipher.getInstance(conf.prop.getProperty("cipherToEncryptSymmetricKey"));
        cipherToEncryptSymmetricKey.init(Cipher.ENCRYPT_MODE, keyToEncryptSymmetricKey);
        byte[] encryptedSymmetricKey = cipherToEncryptSymmetricKey.doFinal(symmetricKey.getEncoded());
        String encryptedSymmetricKeyString = Base64.getEncoder().encodeToString(encryptedSymmetricKey);
        conf.store(confPath + ".decryptor", "encryptedSymmetricKeyString", encryptedSymmetricKeyString);
        conf.store(confPath + ".decryptor","mode", "decrypt");
    }

    //Decrypt the ciphertext provided using all the same vars used for encryption
    public static void decrypt(KeyStore ks, Conf conf, KeyPair kp, String inputFile, byte[] signature, String algorithm) throws Exception {
        byte[] cryptData = readFile(inputFile);
        if (!verifySignature(kp, cryptData, signature, algorithm)) {
            System.out.println("Unable to decrypt file: invalid signature");
            return;
        }

        Key privateKey = ks.getKey(conf.prop.getProperty("alias"), conf.prop.getProperty("password").toCharArray());
        String encryptedSymmetricKeyString = conf.prop.getProperty("encryptedSymmetricKeyString");
        byte[] encryptedSymmetricKey = Base64.getDecoder().decode(encryptedSymmetricKeyString);
        SecretKey symmetricKey = DecryptSymmetricKey(conf, privateKey, encryptedSymmetricKey);
        byte[] IVArray = Base64.getDecoder().decode(conf.IVString);
        IvParameterSpec IV = new IvParameterSpec(IVArray);
        byte[] decryptedData = decryptData(inputFile, conf, symmetricKey, cryptData, IV);
        writeFile("decrypted.txt", decryptedData);
    }

    //Decrypt the symmetric key, all vars were saved in conf file during encryption
    public static SecretKey DecryptSymmetricKey(Conf conf, Key privateKey, byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipherToDecryptSymmetricKey = Cipher.getInstance(conf.prop.getProperty("cipherToEncryptSymmetricKey"));
        cipherToDecryptSymmetricKey.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKeyArr = cipherToDecryptSymmetricKey.doFinal(encryptedSymmetricKey);
        SecretKey decryptedSymmetricKey = new SecretKeySpec(decryptedSymmetricKeyArr, "AES");
        return decryptedSymmetricKey;
    }

    public static void main(String[] args) throws Exception {
        //Verify the user provided a configuration file and a data file
        if (args.length != 2) {
            System.out.println("Invalid arguments\n Usage: " + usage);
            return;
        }

        Conf conf = new Conf();
        String confPath = args[0];
        conf.load(confPath);
        String inputPath = args[1];
        KeyStore ks = Crypto.getKeyStore(conf.keyStorePath, conf.password);
        X509Certificate cert = (X509Certificate)ks.getCertificate(conf.alias);
        KeyPair keyPair = Crypto.getKeyPair(cert, ks, conf.alias, conf.password);
        String signAlgorithm = conf.signAlgorithm;
        int keyLength = conf.keyLength;

        byte[] signature = encrypt( cert, keyPair, conf,confPath, inputPath, signAlgorithm, keyLength);
        String base64Signatue = Base64.getEncoder().encodeToString(signature);
        conf.store(confPath , "signature", base64Signatue);
        conf.load(confPath);
        String decInputPath = "encrypted.txt";
        byte[] decSignature = Base64.getDecoder().decode(conf.signature);
        decrypt(ks, conf, keyPair, decInputPath, decSignature, signAlgorithm);
    }

}