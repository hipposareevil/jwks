package com.wpff.jwks;

import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.salesforce.sds.kms.client.kmsOpenAPIJavaClient.model.SmsSignature;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;


import java.net.URI;

import java.util.*;

import java.security.*;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;

@RestController
public class JwtController {

    private static final String HOST = "http://localhost:8080";
    private static final String WELL_KNOWN = HOST + "/.well-known/jwks.json";

    // Contains public + private 
    private final KeyPair rsaKeyPair;
    private final KeyPair rsaKeyPair2;

    private final JWK jwk;
    private final JWK jwk2;

    // elliptic curve
    private JWK ecJwk;

    private com.nimbusds.jose.jwk.ECKey theirJwk;

    // Interact with kms service
    private KeyServiceClient keyClient = KeyServiceClient.getClient();

    /**
     * Create EC and RSA keys
     */
    public JwtController() throws Exception {
        // RSA keys
        // Generate the RSA key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);

        // rsa one
        rsaKeyPair = gen.generateKeyPair();
        // second one
        rsaKeyPair2 = gen.generateKeyPair();

        // Make JWKs
        jwk = makeRsaJwk(rsaKeyPair);
        jwk2 = makeRsaJwk(rsaKeyPair2);

        //////////////
        // elliptic curve

        // this is public JWK, nothing to do signing yet
        this.ecJwk = makeEcJwk();


        // Test theirs
        theirJwk = new ECKeyGenerator(Curve.P_256)
                .keyID("666321")
                .generate();

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
        // Make JWK from public key
        java.security.PublicKey publicKey = this.keyClient.getPublicKey();
        String keyId = this.keyClient.getKeyId();

        JWK jwk = new com.nimbusds.jose.jwk.ECKey.Builder(
                Curve.P_256,
                (ECPublicKey) publicKey)
                .keyID(keyId)
                .build();

        return jwk;
    }


    // Validate RSA
    private String validateToken(String jwtString) throws Exception {
        System.out.println("");
        System.out.println("=====================");
        System.out.println("");

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

            // debug log
            System.out.println("HEADER: " + signedJwt.getHeader());

            // Get header information: jku, alg
            URI jkuUri = signedJwt.getHeader().getJWKURL();

            // Get alg from header
//            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
            JWSAlgorithm expectedJWSAlg = signedJwt.getHeader().getAlgorithm();
            String kid = signedJwt.getHeader().getKeyID();

            // Create a JWT processor for the access tokens
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                    new DefaultJWTProcessor<>();

            // Set the required "typ" header "at+jwt" for access tokens issued by the
            // Connect2id server, may not be set by other servers
            /*
            jwtProcessor.setJWSTypeVerifier(
                    new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWT")));
*/

            // The public RSA keys to validate the signatures will be sourced from the
            // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
            // object caches the retrieved keys to speed up subsequent look-ups and can
            // also handle key-rollover
            JWKSource<SecurityContext> keySource =
                    new RemoteJWKSet<>(jkuUri.toURL());

            // Configure the JWT processor with a key selector to feed matching public
            // keys sourced from the JWK set URL
            JWSVerificationKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
            // Process
            jwtProcessor.setJWSKeySelector(keySelector);

            // Set the required JWT claims for access tokens issued by the Connect2id
            // server, may differ with other servers
            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                    new JWTClaimsSet.Builder().issuer(HOST).build(),
                    new HashSet<>(Arrays.asList("sub", "scp", "exp"))));

// FULLSET                    //new HashSet<>(Arrays.asList("sub", "iat", "exp", "scp", "cid", "jti"))));
// scp, iat, jti, cid]

            // Process the token
            SecurityContext ctx = null; // optional context parameter, not required here
            try {
                JWTClaimsSet claimsSet = jwtProcessor.process(signedJwt, ctx);

                // Print out the token claims set
                return claimsSet.toJSONObject().toString();
            } catch (com.nimbusds.jose.proc.BadJWSException e) {
                e.printStackTrace();
                System.out.println(e.getMessage());
                System.out.println(e.getCause());
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
        System.out.println("");
        System.out.println("");
        System.out.println("=====================");
        System.out.println("VALIDATE TOKEN EC");
        System.out.println("=====================");
        System.out.println("");
        System.out.println("STRING: " + jwtString);
        System.out.println("");

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
            System.out.println();
            System.out.println("JKU: " + jkuUri);
            System.out.println();

            // Get alg from header
//            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
            JWSAlgorithm expectedJWSAlg = signedJwt.getHeader().getAlgorithm();
            String kid = signedJwt.getHeader().getKeyID();

            // Create a JWT processor for the access tokens
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                    new DefaultJWTProcessor<>();

            // Set the required "typ" header "at+jwt" for access tokens issued by the
            // Connect2id server, may not be set by other servers
            /*
            jwtProcessor.setJWSTypeVerifier(
                    new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWT")));
*/

            // The public RSA keys to validate the signatures will be sourced from the
            // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
            // object caches the retrieved keys to speed up subsequent look-ups and can
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
            System.out.println();
            System.out.println("get JWKs from JWK Source (wellknown):");
            jwks.forEach(System.out::println);

            JWK first = jwks.get(0);
            java.security.PublicKey publicKey = first.toECKey().toPublicKey();
            // Get java publickey
            System.out.println("public key:");
            System.out.println(publicKey);

            System.out.println();
            System.out.println();
            Base64URL[] parsedParts = jwt.getParsedParts();
            System.out.println("parsed parts");
            Arrays.stream(parsedParts).forEach(System.out::println);

            // debug log
            System.out.println("");
            System.out.println("HEADER: " + signedJwt.getHeader());
            System.out.println("");
            System.out.println("PAYLOAD: " + signedJwt.getPayload());
            System.out.println("");
            System.out.println("SIGNATURE");
            System.out.println(signedJwt.getSignature());
            System.out.println(signedJwt.getSignature().toString());
            System.out.println(signedJwt.getSignature().decodeToString());

            System.out.println("");
            System.out.println("---------------------");
            System.out.println("expected algorithm: " + expectedJWSAlg);
            System.out.println("expected kid: " + kid);
            System.out.println("key selector: " + keySelector);
            System.out.println(keySelector.getJWKSource());
            System.out.println("is allowed by key selector? " + keySelector.isAllowed(expectedJWSAlg));
            System.out.println();
            System.out.println("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");

            try {
                System.out.println("");
                System.out.println("KMS verification");
                System.out.println("");

                String headerAndPayload = signedJwt.getHeader().toBase64URL().toString() + "." +
                        signedJwt.getPayload().toBase64URL().toString();
                System.out.println("header + payload: " + headerAndPayload);
                System.out.println();
                String base64signature = signedJwt.getSignature().toString();
                System.out.println("base64signature: " + base64signature);
                System.out.println("");
                System.out.println("die?");

                boolean valid = this.keyClient.checkSignature(
                        headerAndPayload, base64signature
                );
                System.out.println("VERIFY using KMS: " + valid);
            }
            catch (Exception e){
                System.out.println("ERROR in verify with KMS");
                System.out.println(e.getMessage());
            }

            System.out.println("");
            System.out.println("%%%%%%%%%%%%%%%%%%%%%%%%%%%");
            System.out.println("");

            // Process
            jwtProcessor.setJWSKeySelector(keySelector);

            // Set the required JWT claims for access tokens issued by the Connect2id
            // server, may differ with other servers
            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                    new JWTClaimsSet.Builder().issuer(HOST).build(),
                    new HashSet<>(Arrays.asList("sub", "scp", "exp"))));

            // Process the token
            try {
                JWTClaimsSet claimsSet = jwtProcessor.process(signedJwt, (SecurityContext) null);

                // Print out the token claims set
                return claimsSet.toJSONObject().toString();
            } catch (com.nimbusds.jose.proc.BadJWSException e) {
                e.printStackTrace();
                System.out.println(e.getMessage());
                System.out.println(e.getCause());
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
    @RequestMapping("/ec/gotJwt_base")
    public String gotJwtEC_base(@RequestParam String scope) throws Exception {
               // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got beer?")
                .issuer(HOST)
                .claim("scp", "superscope")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        // Create the EC signer
        JWSSigner signer = new ECDSASigner(theirJwk);

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(theirJwk.getKeyID())
                        .jwkURL(new URI(WELL_KNOWN))
                        .build(),
                claimsSet);

        // Compute the EC signature
        signedJWT.sign(signer);

        String base64signature = signedJWT.getSignature().toString();
        System.out.println("base64 signature: " + base64signature);

        // Serialize the JWS to compact form
        String s = signedJWT.serialize();

        // CLIENT test
        System.out.println();
        System.out.println("----------------------------------");
        System.out.println("Verify via ECDSA:");
        System.out.println();
        SignedJWT clientside = SignedJWT.parse(s);
        com.nimbusds.jose.jwk.ECKey ecPublicJWK = theirJwk.toPublicJWK();
        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);

        boolean result = clientside.verify(verifier);
        System.out.println("RESULT: " + result);


        // CLIENT

        return s;
    }


    // Create JWT
    @RequestMapping("/ec/gotJwt")
    public String gotJwtEC(@RequestParam String scope) throws Exception {
        System.out.println("");
        System.out.println("-------");
        System.out.println("gotJwtEc");

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got milk?")
                .claim("scp", scope)
                .issuer(HOST)
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        // Convert to base64url
        com.nimbusds.jose.util.Base64URL claims_base64 = new Payload(claimsSet.toJSONObject())
                .toBase64URL();

        // Header
        String keyId = this.keyClient.getKeyId();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(keyId)
                .jwkURL(new URI(WELL_KNOWN))
                .build();
        // convert to base64url
        com.nimbusds.jose.util.Base64URL header_base64 = header.toBase64URL();

        System.out.println("");
        System.out.println("header");
        System.out.println(header_base64);
        System.out.println(header_base64.decodeToString());

        System.out.println("");
        System.out.println("claims/payload:");
        System.out.println(claims_base64);
        System.out.println(claims_base64.decodeToString());

        String dataToSign = header_base64.toString() +
                "." +
                claims_base64.toString();

        System.out.println("");
        System.out.println("DATA: " + dataToSign);

        // Make signature, this will be base64 encoded
        SmsSignature signature = this.keyClient.signData(dataToSign);
        String signatureAsString = signature.getSignature();
        Base64URL signature_base64 = new Base64URL(signatureAsString);

        // TEST
        byte[] der = ECDSA.transcodeSignatureToDER(signature.getSignature().getBytes());

        int rsByteArrayLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());
		//byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(signature.getSignature().getBytes(), rsByteArrayLength);
        byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(der, rsByteArrayLength);
        System.out.println("FOOOO: sign. jwsSignature: " + new String(jwsSignature));
        signature_base64 = Base64URL.encode(jwsSignature);
        // END TEST

        // sign with the 3 parts
        SignedJWT signedJWT = new SignedJWT(
                header_base64,
                claims_base64,
                signature_base64);

        System.out.println("");
        System.out.println("signature: \n" + new String(signature.getSignature()));
        System.out.println("");

        System.out.println("------------------------------------------");
        try {
            // Validate signature

            // public key from JWK
            java.security.PublicKey publicKey = ecJwk.toECKey().toPublicKey();
            // Get java publickey
            System.out.println("Public key:");
            System.out.println(publicKey);
            System.out.println("");

            String headerAndPayload = signedJWT.getHeader().toBase64URL().toString() + "." +
                    signedJWT.getPayload().toBase64URL().toString();

            System.out.println("header payload: " + headerAndPayload);
            String base64signature = signedJWT.getSignature().toString();

            System.out.println("signature from JWT: ");
            System.out.println(base64signature);

            boolean valid = this.keyClient.checkSignature(
                    headerAndPayload, base64signature
            );
            System.out.println("VERIFY: " + valid);

        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("------------------------------------------");

        Base64URL[] parsedParts = signedJWT.getParsedParts();
        System.out.println("parsed parts");
        Arrays.stream(parsedParts).forEach(System.out::println);

        return signedJWT.serialize();
    }


    // Create JWT
    @RequestMapping("/rsa/gotJwt")
    public String gotJwt(@RequestParam String scope) throws Exception {
        System.out.println("-------");
        System.out.println("gotJwt");

        // Get privatekey and kid
        String kid = jwk.getKeyID();
        PrivateKey privateKey = rsaKeyPair.getPrivate();


        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(privateKey);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got milk?")
                .claim("scp", scope)
                .issuer(HOST)
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(kid)
                        .jwkURL(new URI(WELL_KNOWN))
                        .build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        // To serialize to compact form, produces something like
        // eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
        // mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
        // maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
        // -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
        String s = signedJWT.serialize();
        return s;
    }


    // JWKS!
    @RequestMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() throws Exception {
        List<JWK> keys = new ArrayList<JWK>();
        keys.add(jwk.toPublicJWK());
        keys.add(jwk2.toPublicJWK());
        keys.add(ecJwk.toPublicJWK());
        keys.add(theirJwk.toPublicJWK());

        JWKSet set = new JWKSet(keys);
        return set.toJSONObject(true);
    }

    // Validate jwt
    @PostMapping("/rsa/validate")
    String validateRsa(@RequestBody String jwt) throws Exception {
        String result = validateToken(jwt);
        return result;
    }

    // Validate jwt
    @PostMapping("/ec/validate")
    String validateEc(@RequestBody JwtData jwt) throws Exception {
        System.out.println("VALIDATE EC");
        System.out.println(jwt.data);
        String result = validateTokenEc(jwt.data);
        return result;
    }


    // EC
    @RequestMapping("/ec")
    public String ec() throws Exception {
        return ecJwk.toPublicJWK().toString();
    }

    // first RSA
    @RequestMapping("/rsa")
    public String rsa() throws Exception {
        return jwk.toPublicJWK().toString();
    }

}
