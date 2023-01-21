package crypto;
import java.io.*;
import java.util.Objects;
import java.util.Properties;

public class Conf {
    boolean mode=false;
    String password;
    String alias;
    String keyStorePath;
    String signature;
    String signAlgorithm;
    String cipher;
    int keyLength;
    String cipherProvider;
    String signatureProvider;
    String encriptedSymmetricKeyString;
    String IVString;
    Properties prop;

    public Conf() {

    }

    public void store(String path, String fieldName, String fieldValue) throws FileNotFoundException, IOException {
        OutputStream output = new FileOutputStream(path);
        this.prop.setProperty(fieldName, fieldValue);
        this.prop.store(output, null);
    }

    public void load(String path) throws FileNotFoundException, IOException {
        InputStream input = new FileInputStream(path);
        this.prop = new Properties();
        this.prop.load(input);
        this.mode = Objects.equals(this.prop.getProperty("mode"), "encrypt");
        this.password = this.prop.getProperty("password");
        this.alias = this.prop.getProperty("alias");
        this.keyStorePath = this.prop.getProperty("keystore");
        this.cipher = this.prop.getProperty("cipher");
        this.keyLength = Integer.parseInt(this.prop.getProperty("keyLength"));

        //Optional fields
        String signAlgorithm = this.prop.getProperty("signatureAlgorithm");
        if (signAlgorithm == null) {
            signAlgorithm = "SHA1withRSA";
        }
        this.signAlgorithm = signAlgorithm;

        String signatureProvider = this.prop.getProperty("signatureProvider");
        if (signatureProvider == null) signatureProvider="SunJCE";
        this.signatureProvider = signatureProvider;

        String cipherProvider = this.prop.getProperty("cipherProvider");
        if (cipherProvider == null){
            cipherProvider = "SunJCE";
        }
        this.cipherProvider =cipherProvider;

        String signature = this.prop.getProperty("signature");
        // Signature is optional, and required only on decrypt mode.
        if (signature != null) {
            this.signature = signature;
        }

        String encriptedSymmetricKeyString = this.prop.getProperty("encriptedSymmetricKeyString");
        if (encriptedSymmetricKeyString  != null) {
            this.encriptedSymmetricKeyString = encriptedSymmetricKeyString;
        }

        String IVString = this.prop.getProperty("IVString");
        // IV is optional, and required only on decrypt mode.
        if (IVString != null) {
            this.IVString = IVString;
        }
    }
}