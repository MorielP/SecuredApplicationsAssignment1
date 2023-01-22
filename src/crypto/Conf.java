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
    int keyLength;
    String cipherProvider;
    String signatureProvider;
    String encryptedSymmetricKeyString;
    String IVString;
    String cipherToEncryptSymmetricKey;
    String cipherTpEncryptData;
    Properties prop;

    public Conf() {

    }

    public void store(String path, String fieldName, String fieldValue) throws IOException {
        OutputStream output = new FileOutputStream(path);
        this.prop.setProperty(fieldName, fieldValue);
        this.prop.store(output, null);
    }

    public void load(String path) throws IOException {
        InputStream input = new FileInputStream(path);
        this.prop = new Properties();
        this.prop.load(input);
        this.mode = Objects.equals(this.prop.getProperty("mode"), "encrypt");
        this.password = this.prop.getProperty("password");
        this.alias = this.prop.getProperty("alias");
        this.keyStorePath = this.prop.getProperty("keystore");
        //this.cipher = this.prop.getProperty("cipher");
        this.keyLength = Integer.parseInt(this.prop.getProperty("keyLength"));
        this.cipherToEncryptSymmetricKey = this.prop.getProperty("cipherToEncryptSymmetricKey");
        this.cipherTpEncryptData = this.prop.getProperty("cipherTpEncryptData");
        this.cipherProvider=this.prop.getProperty("cipherProvider");

        //Optional fields
        String signAlgorithm = this.prop.getProperty("signatureAlgorithm");
        if (signAlgorithm == null) {
            signAlgorithm = "SHA1withRSA";
        }
        this.signAlgorithm = signAlgorithm;

        String signatureProvider = this.prop.getProperty("signatureProvider");
        if (signatureProvider != null) this.signatureProvider = signatureProvider;
        if (signatureProvider == null) this.signatureProvider="SunJCE";

        String cipherProvider = this.prop.getProperty("cipherProvider");
        if (cipherProvider == null) this.cipherProvider = "SunJCE";
        else this.cipherProvider = cipherProvider;

        String signature = this.prop.getProperty("signature");
        // Signature is optional, and required only on decrypt mode.
        if (signature != null) {
            this.signature = signature;
        }

        String encryptedSymmetricKeyString = this.prop.getProperty("encriptedSymmetricKeyString");
        if (encryptedSymmetricKeyString  != null) {
            this.encryptedSymmetricKeyString = encryptedSymmetricKeyString;
        }

        String IVString = this.prop.getProperty("IVString");
        // IV is optional, and required only on decrypt mode.
        if (IVString != null) {
            this.IVString = IVString;
        }

    }
}