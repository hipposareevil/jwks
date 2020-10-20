package com.wpff.jwks;

import com.salesforce.sds.kms.client.ApiException;
import com.salesforce.sds.kms.client.kmsOpenAPIJavaClient.model.*;
import com.salesforce.sds.kms.client.wrapper.DynamicKeyStoreConfig;
import com.salesforce.sds.kms.client.wrapper.KmsClient;
import org.spongycastle.openssl.PEMWriter;


import java.io.File;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Util to interface with KMS api.
 */
public class KeyServiceClient {

    // current key in KMS
    private String keyId =
            "1:2:E00CB9B35823BD2AAB612E696E21A63622BB9A432A2F282911056A228C29B92F:e2886d55-04f1-4323-b1a7-c21224a40394";

    // Retrieve first current key from api
    private String currentKeyVersion = null;

    // Used to create Signatures
    public static final String ENCODING = "SHA256withECDSA";

    // Public CA for server
    // in k8s: /etc/identity/ca
    public static final String CA_PATH = "/tmp/kms/dktool_repo/ca";

    // This is where client (our) pems files are:
    // dktool_repo/user/client/certificates/client.pem
    // dktool_repo/user/client/keys/client-key.pem
    // in k8s: /etc/identity/client
    public static final String MONITORING_DIR = "/tmp/kms/dktool_repo/user/client";

    // Role for creating the Tenant
    public static final String ROLE = "hawking.superfunk";

    public static final String baseUrl = "https://api.kms.crypto.dev1-uswest2.aws.sfdc.cl";

    // KMS client
    private final KmsClient client;

    // Caches public key
    private java.security.PublicKey cachePublicKey = null;


    // One util
    private static final KeyServiceClient singleton = new KeyServiceClient();

    /**
     * Get util singleton
     *
     * @return
     */
    public static KeyServiceClient getClient() {
        return singleton;
    }

    /**
     * Get key as PEM format
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static String getAsPem(java.security.PublicKey key) throws Exception {
        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(stringWriter);
        pemWriter.writeObject(key);
        pemWriter.close();
        String pem = stringWriter.toString();
        return pem;
    }

    /**
     * Create client to KMS api.  Get current key version
     */
    public KeyServiceClient() {
        // validate the paths
        File ca = new File(CA_PATH);
        if (!ca.exists() || !ca.canRead()) {
            System.out.println("NO CA PATH: " + CA_PATH);
        }
        File md = new File(MONITORING_DIR);
        if (!md.exists() || !ca.canRead()) {
            System.out.println("NO monitoring PATH: " + MONITORING_DIR);
        }

        System.out.println("Using KMS endpoint: " + baseUrl);
        this.client = new KmsClient.KmsClientBuilder()
                .withBaseUrl(baseUrl)
                .withDynamicKeyStoreConfig(new DynamicKeyStoreConfig(CA_PATH, MONITORING_DIR))
                .build();

        KeyVersionList keyVersions = null;
        System.out.println("Getting key versions for keyid: " + keyId);
        try {
            keyVersions = this.client.kmsApi().listKeyVersions(keyId,
                    null, null, true,
                    false, true, 10, null);
        } catch (ApiException e) {
            e.printStackTrace();
        }

        // Get current key version
        if (keyVersions != null && keyVersions.getItems().size() >= 1) {
            KeyVersion version = keyVersions.getItems().get(0);
            this.currentKeyVersion = version.getVersionId().toString();
            System.out.println("VERSION: " + version);
        }
        System.out.println("current key version: " + currentKeyVersion);

    }


    /**
     * Get java.security PublicKey from KMS. Caches the key.
     *
     * @return public key
     * @throws Exception
     */
    public java.security.PublicKey getPublicKey() throws Exception {
        if (cachePublicKey == null) {
            PublicKey kmsPublicKey = client.
                    kmsApi().
                    getPublicKey(this.keyId, this.currentKeyVersion, null, null);
            this.cachePublicKey = toECPub(kmsPublicKey);
        }
        return this.cachePublicKey;
    }

    /**
     * Get private key
     *
     * @return private key
     * @throws Exception
     */
    public java.security.interfaces.ECPrivateKey getPrivateKey() throws Exception {
        String versionId = this.currentKeyVersion;
        String xSFDCCustomerID = null;
        String xCorrelationID = null;
        KeyVersion result = this.client.kmsApi().
                retrieveKeyMaterialByVersionId(versionId, xSFDCCustomerID, xCorrelationID);

        ECPrivateKey key = toPrivate(result.getPlaintext());

        return key;
    }

    /**
     * Retrieve the current KID
     *
     * @return
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * Return the current version for key.
     *
     * @return
     */
    public String getCurrentKeyVersion() {
        return currentKeyVersion;
    }


    /**
     * Sign the incoming data and return the SmsSignature, from which you can get the
     * base64 encoded string.
     *
     * @param dataToSign What to sign
     * @return Signature. Call getSignature to get base64 encoded string.
     * @throws ApiException
     */
    public SmsSignature signData(String dataToSign) throws ApiException {
        String data = Base64.getEncoder().encodeToString(dataToSign.getBytes());
        SignRequest signRequest = (new SignRequest()).data(data);
        SmsSignature signature = client.kmsApi().sign(
                this.keyId,
                this.currentKeyVersion,
                signRequest, null, null);

        return signature;
    }

    /**
     * Validate if the signature verifies against the incoming raw data.
     * This will use the current public key
     *
     * @param rawData   what was signed
     * @param signature base64 encoded signature
     * @return
     */
    public boolean checkSignature(String rawData, String signature) throws Exception {
        byte[] decodedSignature = Base64.getDecoder().decode(signature.getBytes());
        java.security.Signature signer = Signature.getInstance(ENCODING);
        java.security.PublicKey publicKey = getPublicKey();

        System.out.println("CHECK SIGNATURE: algo: " + publicKey.getAlgorithm());
        System.out.println("CHECK SIGNATURE: format: " + publicKey.getFormat());

        // Initialize signer with public key
        signer.initVerify(publicKey);
        // Update to use the raw data
        signer.update(rawData.getBytes());

        boolean verified = signer.verify(decodedSignature);

        return verified;
    }


    ///////////////////////////////////


    private static java.security.PublicKey toECPub(PublicKey publicKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return toPub(publicKey, kf);
    }

    private static java.security.PublicKey toPub(PublicKey publicKey, KeyFactory kf) throws Exception {
        final String publicKeyContent = getPublicKeyContent(publicKey);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        final java.security.PublicKey pubKey = kf.generatePublic(keySpecX509);
        System.out.println("Got pub key as " + pubKey.toString());
        return pubKey;
    }

    /**
     * Generate PrivateKey from incoming pem string
     *
     * @param privateKey
     * @return
     * @throws Exception
     */
    private static java.security.interfaces.ECPrivateKey toPrivate(String privateKey) throws Exception {
        // remove the header/footer
        final String keyContent = getPrivateKeyContent(privateKey);
        KeyFactory kf = KeyFactory.getInstance("EC");

        // Create spec to decode bits
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(keyContent.getBytes()));

        // make private key. convert to EC key as we're using elliptical curve
        PrivateKey key = kf.generatePrivate(keySpec);
        return (java.security.interfaces.ECPrivateKey) key;
    }


    private static String getPublicKeyContent(PublicKey publicKey) {
        return publicKey.getPublic()
                .replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
    }

    private static String getPrivateKeyContent(String key) {
        return key
                .replaceAll("\\n", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
    }


}
