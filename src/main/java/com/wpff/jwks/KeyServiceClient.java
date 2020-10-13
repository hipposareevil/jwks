package com.wpff.jwks;

import com.salesforce.sds.kms.client.ApiException;
import com.salesforce.sds.kms.client.kmsOpenAPIJavaClient.model.*;
import com.salesforce.sds.kms.client.wrapper.DynamicKeyStoreConfig;
import com.salesforce.sds.kms.client.wrapper.KmsClient;


import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Util to interface with KMS api.
 */
public class KeyServiceClient {

    // current key in KMS
    private String keyId =
            "1:2:E00CB9B35823BD2AAB612E696E21A63622BB9A432A2F282911056A228C29B92F:2861f689-4e24-4999-ab97-f0541ba2d288";
    // Retrieve first current key from api
    private String currentKeyVersion = null;

    // Used to create Signatures
    public static final String ENCODING = "SHA256withECDSA";

    // Public CA for server
    // in k8s: /etc/identity/ca
    public static final String CA_PATH = "/work/scratch/kms/dktool_repo/ca";

    // This is where client (our) pems files are:
    // dktool_repo/user/client/certificates/client.pem
    // dktool_repo/user/client/keys/client-key.pem
    // in k8s: /etc/identity/client
    public static final String MONITORING_DIR = "/work/scratch/kms/dktool_repo/user/client";

    // Role for creating the Tenant
    public static final String ROLE = "hawking.superfunk";

    // KMS client
    private final KmsClient client;

    // One util
    private static final KeyServiceClient singleton = new KeyServiceClient();

    /**
     * Get util singleton
     * @return
     */
    public static KeyServiceClient getClient() {
        return singleton;
    }

    /**
     * Create client to KMS api.  Get current key version
     */
    public KeyServiceClient() {
        this.client = new KmsClient.KmsClientBuilder()
                .withBaseUrl("https://api.kms.crypto.dev1-uswest2.aws.sfdc.cl")
                .withDynamicKeyStoreConfig(new DynamicKeyStoreConfig(CA_PATH, MONITORING_DIR))
                .build();

        KeyVersionList keyVersions = null;
        try {
            keyVersions = this.client.kmsApi().listKeyVersions(keyId, null, null, true,
                    false, false, 10, null);
        } catch (ApiException e) {
            e.printStackTrace();
        }

        // Get current key version
        if (keyVersions.getItems().size() >= 1) {
            KeyVersion version = keyVersions.getItems().get(0);
            this.currentKeyVersion = version.getVersionId().toString();
        }
        System.out.println("current key version: " + currentKeyVersion);
    }

    private java.security.PublicKey cachePublicKey = null;
    /**
     * Get java.security PublicKey. Caches the key.
     *
     * @return public key
     * @throws Exception
     */
    public java.security.PublicKey getPublicKey() throws Exception {
        if (cachePublicKey == null) {
            PublicKey kmsPublicKey = client.kmsApi().getPublicKey(this.keyId, this.currentKeyVersion, null, null);
            this.cachePublicKey = toECPub(kmsPublicKey);
        }
        return this.cachePublicKey;
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
     * @param signature base64 encoded signature
     * @param rawData what was signed
     * @return
     */
    public boolean checkSignature(String signature, String rawData) throws Exception {
        byte[] decodedSignature = Base64.getDecoder().decode(signature.getBytes());
        java.security.Signature signer = Signature.getInstance(ENCODING);
        java.security.PublicKey publicKey = getPublicKey();

        // Initialize signer with public key
        signer.initVerify(publicKey);
        // Update to use the raw data
        signer.update(rawData.getBytes());

        boolean verified = signer.verify(decodedSignature);

        return verified;
    }


    ///////////////////////////////////

    private java.security.PublicKey toRsaPub(PublicKey publicKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return toPub(publicKey, kf);
    }

    private java.security.PublicKey toECPub(PublicKey publicKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return toPub(publicKey, kf);
    }

    private java.security.PublicKey toPub(PublicKey publicKey, KeyFactory kf) throws Exception {
        final String publicKeyContent = getPublicKeyContent(publicKey);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        final java.security.PublicKey pubKey = kf.generatePublic(keySpecX509);
        System.out.println("Got pub key as " + pubKey.toString());
        return pubKey;
    }

    private String getPublicKeyContent(PublicKey publicKey) {
        return publicKey.getPublic()
                .replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
    }


}
