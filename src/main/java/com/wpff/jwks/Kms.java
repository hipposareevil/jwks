package com.wpff.jwks;

import com.salesforce.sds.kms.client.kmsOpenAPIJavaClient.model.*;
import com.salesforce.sds.kms.client.wrapper.DynamicKeyStoreConfig;
import com.salesforce.sds.kms.client.wrapper.KmsClient;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;


import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@RestController
public class Kms {

    // Public CA for server
    // in k8s: /etc/identity/ca
    public static final String CA_PATH = "/work/scratch/kms/dktool_repo/ca";

    // This is where client (our) pems files are:
    // dktool_repo/user/client/certificates/client.pem
    // dktool_repo/user/client/keys/client-key.pem
    // in k8s: /etc/identity/client
    public static final String MONITORING_DIR = "/work/scratch/kms/dktool_repo/user/client";

    public static final String ROLE = "hawking.superfunk";
    private final KmsClient client;
    private final KeyServiceClient keyServiceClient;

    // TEST
    private String ecKid = "1:2:E00CB9B35823BD2AAB612E696E21A63622BB9A432A2F282911056A228C29B92F:2861f689-4e24-4999-ab97-f0541ba2d288";
    private String ecKidVersion = "042801c0-b7eb-4da9-ac65-f90eda4f02a2";

// from postman
//    private String ecSignature = "MEQCIBsREE+K5WwUAL5CajyXtWeQPl4NMQ/331aPN/yKzZGKAiBP9w2WQuX2SnFpO9seWJqCOiMjsPhk1/PxSIQLNKisfA==";
    // from curl
    private String ecSignature = "MEUCIFikVwesncyPHzLNzs7frQsYunJeyIcLgGVD/81Af160AiEAhMNlw2cRa/nZdZ9crGjo5GgNSy94jaQ26k+kGtanWV0=";
    // from client
//    private String ecSignature = "MEYCIQDsEm3G2WAJYUGiW3NibkFBbo6wfWSaR0H7dYF23MG5FAIhAJ6gYGGbOXV08x0RrUQoCSOLmsj9Msai816aZTDi/rtn";

    private String dataToSign = "test";

    private String payload_64 = "dGVzdAo=";


    // TEST

    public Kms() throws Exception {
        client = new KmsClient.KmsClientBuilder()
                .withBaseUrl("https://api.kms.crypto.dev1-uswest2.aws.sfdc.cl")
                .withDynamicKeyStoreConfig(new DynamicKeyStoreConfig(CA_PATH, MONITORING_DIR))
                .build();

        keyServiceClient = KeyServiceClient.getClient();
    }

    @RequestMapping("/kms/sign")
    public String signKeys(@RequestParam String dataToSign) throws Exception {
        System.out.println("Sign this -> " + dataToSign);
        java.security.PublicKey publicKey = this.keyServiceClient.getPublicKey();

        SmsSignature signature = this.keyServiceClient.signData(dataToSign);
        String signatureString = signature.getSignature();
        byte[] decodedSignatureString = Base64.getDecoder().decode(signatureString.getBytes());
        System.out.println("signkeys signature: " + signatureString);

        boolean verified = this.keyServiceClient.checkSignature(signatureString, dataToSign);
        System.out.println("verified? " + verified);

        return signature.getSignature();
    }

    @RequestMapping("/kms/test")
    public String testKeys() throws Exception {
        // Get public key
        PublicKey x = client.kmsApi().getPublicKey(ecKid, ecKidVersion, null, null);
        java.security.PublicKey publicKey = toECPub(x);

        System.out.println("kms/test");
        System.out.println(x);
        System.out.println(x.getPublic());
        System.out.println(publicKey);

        // Verify signature
        {
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initVerify(publicKey);
            signer.update(dataToSign.getBytes());
            boolean verified = signer.verify(Base64.getDecoder().decode(ecSignature.getBytes()));

            System.out.println("verified? " + verified);
            System.out.println("signature: " + ecSignature);
            System.out.println("");
            System.out.println("");
            System.out.println("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
            System.out.println("");
        }

        // Do with client
        {
            String data = Base64.getEncoder().encodeToString(dataToSign.getBytes());
            SignRequest req = (new SignRequest()).data(data);
            SmsSignature signature = client.kmsApi().sign(
                ecKid,
                ecKidVersion,
                req, null, null);

            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initVerify(publicKey);
            signer.update(dataToSign.getBytes());


            boolean verified = signer.verify(Base64.getDecoder().decode(signature.getSignature().getBytes()));
            System.out.println("verified2 ? " + verified);
            System.out.println("signature: " + signature.getSignature());
        }

        return "public key: " + publicKey;
    }

    @RequestMapping("/kms/create")
    public String createKey() throws Exception {
        Tenant myselfTenant = new Tenant().role(ROLE);
        // Request
        CreateKeyRequest createKeyRequest = new CreateKeyRequest()
                .deletable(true)
                .owner(myselfTenant)
                .type(CreateKeyRequest.TypeEnum.ECDSA_NIST_P_256);

        // Creat ekey
        Key key = client.kmsApi().createKey(createKeyRequest, null, null, false);

        return ""+  key.getCurrentVersionId();
    }



    // ----------------------------------------------------------------------


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
        //System.out.println("Got pub key as " + pubKey.toString());
        return pubKey;
    }

    private String getPublicKeyContent(PublicKey publicKey) {
        return publicKey.getPublic()
                .replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
    }



}
