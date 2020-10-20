package com.wpff.jwks;


import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.salesforce.sds.kms.client.kmsOpenAPIJavaClient.model.SmsSignature;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;


import java.net.URI;

import java.util.*;

import java.security.*;
import java.security.interfaces.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;

@RestController
public class KmsController {
    // where we live - http://localhost:8080
    @Value("${host}")
    private String host;

    private String getWellKnownUrl() {
        String well_known_uri = this.host + "/kms/.well-known/jwks.json";
        return well_known_uri;
    }

    // Contains public + private
    private final KeyPair rsaKeyPair;

    private final JWK jwk;

    // elliptic curve
    private JWK ecKmsJwk;

    private com.nimbusds.jose.jwk.ECKey ecJoseJwk;

    // Interact with kms service
    private KeyServiceClient keyClient = KeyServiceClient.getClient();


    /**
     * Create EC and RSA keys
     */
    public KmsController() throws Exception {
        // RSA keys
        // Generate the RSA key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);

        // rsa one
        rsaKeyPair = gen.generateKeyPair();

        // Make JWKs
        jwk = makeRsaJwk(rsaKeyPair);

        //////////////
        // elliptic curve

        // this is public JWK, just contains public key and KID
        this.ecKmsJwk = makeEcJwk();

        // Test nimbus-jose
        this.ecJoseJwk = new ECKeyGenerator(Curve.P_256)
                .keyID("666321")
                .generate();
    }

    // print out
    private void logit(Object log) {
        System.out.println(log.toString());
    }
    private void logit() {
        System.out.println("");
    }




    // Make jwk from RSA keypair
    private JWK makeRsaJwk(KeyPair keyPair) {
        JWK jwk = new com.nimbusds.jose.jwk.RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .build();

        return jwk;
    }

    /**
     * Make an EC JWK
     *
     * @return
     */
    private JWK makeEcJwk() throws Exception {
        // Make JWK from public key retrieved from KMS
        java.security.PublicKey publicKey = this.keyClient.getPublicKey();
        String keyId = this.keyClient.getKeyId();

        JWK jwk = new com.nimbusds.jose.jwk.ECKey.Builder(
                Curve.P_256,
                (ECPublicKey) publicKey)
                .keyID(keyId)
                .build();

        return jwk;
    }


    // Validate JWT
    // normal processing
    private String validateToken(String jwtString) throws Exception {
        JWT jwt = JWTParser.parse(jwtString);

        // Check the JWT type
        if (jwt instanceof PlainJWT) {
            PlainJWT plainObject = (PlainJWT) jwt;
            // continue processing of plain JWT...
            return "plain";
        } else if (jwt instanceof SignedJWT) {
            // SIGNED
            SignedJWT signedJwt = (SignedJWT) jwt;

            // debug log
            logit("HEADER: " + signedJwt.getHeader());

            // Get header information: jku, alg
            URI jkuUri = signedJwt.getHeader().getJWKURL();

            // Get alg from header
            JWSAlgorithm expectedJWSAlg = signedJwt.getHeader().getAlgorithm();
            String kid = signedJwt.getHeader().getKeyID();

            // Create a JWT processor for the access tokens
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                    new DefaultJWTProcessor<>();

            // The RemoteJWKSet
            // object caches the retrieved keys to speed up subsequent look-ups and can
            // also handle key-rollover
            JWKSource<SecurityContext> keySource =
                    new RemoteJWKSet<>(jkuUri.toURL());

            // Configure the JWT processor with a key selector to feed matching public
            // keys sourced from the JWK set URL
            JWSVerificationKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);

            // Set the required JWT claims for access tokens issued by the Connect2id
            // server, may differ with other servers
            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                    new JWTClaimsSet.Builder().issuer(this.host).build(),
                    new HashSet<>(Arrays.asList("sub", "scp", "exp"))));

            // Process the token
            SecurityContext ctx = null; // optional context parameter, not required here
            try {
                JWTClaimsSet claimsSet = jwtProcessor.process(signedJwt, ctx);

                // Print out the token claims set
                logit(claimsSet.toJSONObject().toString());

                // return claims
                return claimsSet.toJSONObject().toString();
            } catch (com.nimbusds.jose.proc.BadJWSException e) {
                e.printStackTrace();
            }

        } else if (jwt instanceof EncryptedJWT) {
            EncryptedJWT jweObject = (EncryptedJWT) jwt;
            // continue with decryption...
            return "encrypted";
        }

        return "unknown or error";
    }

    // Validate EC token
    private String validateTokenEc(String jwtString) throws Exception {
        logit("");
        logit("");
        logit("=====================");
        logit("VALIDATE TOKEN ");
        logit("=====================");
        logit("");
        logit("STRING: " + jwtString);
        logit("");

        JWT jwt = null;
        try {
            jwt = JWTParser.parse(jwtString);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Check the JWT type
        if (jwt instanceof PlainJWT) {
            PlainJWT plainObject = (PlainJWT) jwt;
            // continue processing of plain JWT...
            return "plain";
        } else if (jwt instanceof SignedJWT) {
            // SIGNED
            SignedJWT signedJwt = (SignedJWT) jwt;

            // Get header information: jku, alg
            URI jkuUri = signedJwt.getHeader().getJWKURL();

            // Get alg from header
            JWSAlgorithm expectedJWSAlg = signedJwt.getHeader().getAlgorithm();
            String kid = signedJwt.getHeader().getKeyID();

            // Create a JWT processor for the access tokens
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                    new DefaultJWTProcessor<>();

            // The RemoteJWKSet object caches the retrieved keys
            // to speed up subsequent look-ups and can
            // also handle key-rollover
            JWKSource<SecurityContext> keySource =
                    new RemoteJWKSet<>(jkuUri.toURL());

            // Configure the JWT processor with a key selector to feed matching public
            // keys sourced from the JWK set URL
            JWSVerificationKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

            // Public key
            JWKMatcher matcher = new JWKMatcher.Builder().keyID(this.keyClient.getKeyId()).build();
            JWKSelector selector = new JWKSelector(matcher);
            JWKSource<SecurityContext> source = keySelector.getJWKSource();
            List<JWK> jwks = source.get(selector, null);


            logit();
            logit("JKU: " + jkuUri);
            logit("get JWKs from JWK Source (.well-known):");
            jwks.forEach(System.out::println);
            logit();
            logit();


            // Get first matching one
            JWK first = jwks.get(0);
            java.security.PublicKey publicKey = first.toECKey().toPublicKey();
            // Get java publickey
            logit("public key:");
            logit(publicKey);
            System.out.println(KeyServiceClient.getAsPem(publicKey));


            logit();
            logit();
            Base64URL[] parsedParts = jwt.getParsedParts();
            logit("parsed parts");
            Arrays.stream(parsedParts).forEach(System.out::println);

            // debug log
            logit("");
            logit("HEADER: " + signedJwt.getHeader());
            logit("");
            logit("PAYLOAD: " + signedJwt.getPayload());
            logit("");
            logit("SIGNATURE");
            logit(signedJwt.getSignature());
            logit(signedJwt.getSignature().toString());
            logit(signedJwt.getSignature().decodeToString());

            logit("");
            logit("expected algorithm: " + expectedJWSAlg);
            logit("expected kid: " + kid);
            logit("key selector: " + keySelector);
            logit(keySelector.getJWKSource());
            logit();

            try {
                logit("--------------------");
                logit("KMS verification");
                logit("");

                String headerAndPayload = signedJwt.getHeader().toBase64URL().toString() + "." +
                        signedJwt.getPayload().toBase64URL().toString();
                logit("header + payload: " + headerAndPayload);
                logit();
                String base64signature = signedJwt.getSignature().toString();
                logit("base64signature: " + base64signature);
                logit("");

                boolean valid = this.keyClient.checkSignature(
                        headerAndPayload, base64signature
                );
                logit("Valid (using KMS) and our key client --> " + valid);
                logit();
            }
            catch (Exception e){
                logit("ERROR in verify with KMS");
                logit(e.getMessage());
            }

            logit("");

            // Normal Process
            jwtProcessor.setJWSKeySelector(keySelector);

            // Set the required JWT claims for access tokens issued by the Connect2id
            // server, may differ with other servers
            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                    new JWTClaimsSet.Builder().issuer(this.host).build(),
                    new HashSet<>(Arrays.asList("sub", "scp", "exp"))));

            // Process the token
            try {
                JWTClaimsSet claimsSet = jwtProcessor.process(signedJwt, (SecurityContext) null);

                logit(claimsSet.toJSONObject().toString());

                // Print out the token claims set
                return claimsSet.toJSONObject().toString();
            } catch (com.nimbusds.jose.proc.BadJWSException e) {
                logit();
                logit("Error using JWT processor to validate: " + e.getMessage());
                e.printStackTrace();;
                return(e.getMessage());
            }

        } else if (jwt instanceof EncryptedJWT) {
            EncryptedJWT jweObject = (EncryptedJWT) jwt;
            // continue with decryption...
            return "encrypted";
        }

        return "unknown or error";
    }


    ///////////////////////////////////////////////////////////
    //
    // endpoints
    //
    ///////////////////////////////////////////////////////////

    // Create JWT
    @RequestMapping("/kms/normal/gotJwt")
    public String gotJwtEC_base(@RequestParam String scope) throws Exception {
        logit();
        logit();
        logit();
        logit("-------------");
        logit("normal/gotJwt");

               // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got (normal) milk?")
                .issuer(this.host)
                .claim("scp", "superscope")
                .expirationTime(new Date(new Date().getTime() + 600 * 1000))
                .build();

        // Create the EC signer
        JWSSigner signer = new ECDSASigner(ecJoseJwk);

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(ecJoseJwk.getKeyID())
                .jwkURL(new URI(getWellKnownUrl()))
                        .build(),
                claimsSet);

        // Compute the EC signature
        signedJWT.sign(signer);

        // Serialize the JWS to compact form
        String serializedSignature = signedJWT.serialize();

        // CLIENT test
        logit();
        logit("----------------------------------");
        logit("Verify via ECDSA:");
        logit();
        SignedJWT clientside = SignedJWT.parse(serializedSignature);
        com.nimbusds.jose.jwk.ECKey ecPublicJWK = ecJoseJwk.toPublicJWK();
        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);

        boolean result = clientside.verify(verifier);
        logit("RESULT: " + result);

        System.out.println(KeyServiceClient.getAsPem(ecPublicJWK.toPublicKey()));

        logit();
        logit("----------------------------------");
        logit();
        // CLIENT

        return serializedSignature;
    }


    // Create JWT using KMS signature
    @RequestMapping("/kms/kms/gotJwt")
    public String gotJwtEC(@RequestParam String scope) throws Exception {
            logit();
            logit();
            logit();
        logit("-------------");
        logit("kms/gotJwt");
        logit("");

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got (kms) milk?")
                .claim("scp", scope)
                .issuer(this.host)
                .expirationTime(new Date(new Date().getTime() + 600 * 1000))
                .build();

        // Convert to base64url
        com.nimbusds.jose.util.Base64URL claims_base64 = new Payload(claimsSet.toJSONObject())
                .toBase64URL();

        // Header
        String keyId = this.keyClient.getKeyId();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(keyId)
                .jwkURL(new URI(getWellKnownUrl()))
                .build();
        // convert to base64url
        com.nimbusds.jose.util.Base64URL header_base64 = header.toBase64URL();

        logit("");
        logit("header");
        logit(header_base64);
        logit(header_base64.decodeToString());

        logit("");
        logit("claims/payload:");
        logit(claims_base64);
        logit(claims_base64.decodeToString());

        // what to sign = header + . + claims/payload
        String dataToSign =
                header_base64.toString() +
                "." +
                claims_base64.toString();

        logit("");
        logit("DATA to sign: " + dataToSign);

        // Make signature with KMS, this will be base64 encoded
        SmsSignature signature = this.keyClient.signData(dataToSign);
        String signatureAsString = signature.getSignature();
        Base64URL signature_base64 = new Base64URL(signatureAsString);

        logit("Signature: " + signatureAsString);
        logit("Signature: " + new String(signature_base64.decode()));

        // TEST with der?
        if (1 == 1) {
            int rsByteArrayLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());
            //byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(signature.getSignature().getBytes(), rsByteArrayLength);
            logit("array length: " + rsByteArrayLength);
            byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(signature.getSignature().getBytes(), rsByteArrayLength);
            logit("XXXX: sign. jwsSignature: " + new String(jwsSignature));
            signature_base64 = Base64URL.encode(jwsSignature);
        }
        // END TEST


        // Create signed JWT with the header, claims, and signature
        // sign with the 3 parts
        SignedJWT signedJWT = new SignedJWT(
                header_base64,
                claims_base64,
                signature_base64);

        logit("");
        logit("signature: \n" + new String(signature.getSignature()));
        logit("");


        // TEST with ECDSA/normal route
        if (1 == 1) {
            java.security.PublicKey publicKey = ecKmsJwk.toECKey().toPublicKey();
            JWSVerifier verifier = new ECDSAVerifier(ecKmsJwk.toECKey().toECPublicKey());

            String jwtString = signedJWT.serialize();
            logit("");
            logit("Testing with ECDSA");
            logit("");

            logit("public key used:");
              System.out.println(KeyServiceClient.getAsPem(publicKey));

            logit("JWT: " + jwtString);
            JWT incomingJwt = JWTParser.parse(jwtString);
            JWSObject jwsObject = (SignedJWT) incomingJwt;
            boolean verified = jwsObject.verify(verifier);

            logit("---> Verified via ECDSA: " + verified);
            logit("");
            logit("DONE Testing with ECDSA");
            logit("");
        }
        // end TEST 2

        if (1 == 1) {
            try {
                // Validate signature via 

                // public key from JWK
                java.security.PublicKey publicKey = ecKmsJwk.toECKey().toPublicKey();
                logit("Public key:");
                logit(publicKey);
                logit("");

                // Get the data we sent to be signed
                String headerAndPayload = signedJWT.getHeader().toBase64URL().toString() + "." +
                        signedJWT.getPayload().toBase64URL().toString();

                logit("header payload, should match 'DATA to sign' above: ");
                logit(headerAndPayload);

                String base64signature = signedJWT.getSignature().toString();
                logit("signature from JWT: ");
                logit(base64signature);

                boolean valid = this.keyClient.checkSignature(
                    headerAndPayload, base64signature
                                                              );
                logit("---> VERIFY with kms and key client: " + valid);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // return jwt
        
        return signedJWT.serialize();
    }

    // Create RSA JWT
    @RequestMapping("/kms/rsa/gotJwt")
    public String gotJwt(@RequestParam String scope) throws Exception {
               logit();
               logit();
               logit();
               logit();
        logit("-------------");

        logit("rsa/gotJwt");
        logit("");

        // Get privatekey and kid
        String kid = jwk.getKeyID();
        PrivateKey privateKey = rsaKeyPair.getPrivate();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(privateKey);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got RSA milk?")
                .claim("scp", scope)
                .issuer(host)
                .expirationTime(new Date(new Date().getTime() + 600 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(kid)
                .jwkURL(new URI(getWellKnownUrl()))
                        .build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        String s = signedJWT.serialize();
        return s;
    }


    // JWKS
    @RequestMapping("/kms/.well-known/jwks.json")
    public Map<String, Object> jwks() throws Exception {
        List<JWK> keys = new ArrayList<JWK>();
        keys.add(jwk.toPublicJWK());
        keys.add(ecKmsJwk.toPublicJWK());
        keys.add(ecJoseJwk.toPublicJWK());

        JWKSet set = new JWKSet(keys);
        return set.toJSONObject(true);
    }

    // Validate jwt
    @PostMapping("/kms/normal/validate")
    String validateRsa(@RequestBody JwtData jwt) throws Exception {
        String result = validateToken(jwt.data);
        return result;
    }

    // Validate jwt with KMS validation
    @PostMapping("/kms/kms/validate")
    String validateEc(@RequestBody JwtData jwt) throws Exception {
        String result = validateTokenEc(jwt.data);
        return result;
    }

}

