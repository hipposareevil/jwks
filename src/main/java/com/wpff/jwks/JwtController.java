package com.wpff.jwks;

import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;


import java.io.*;
import java.net.URL;
import java.net.URI;

import java.util.*;

import java.security.*;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.*;

import java.security.cert.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
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

    // eliptic curve
    private JWK ecJwk;
    private String ecKid = "1:2:E00CB9B35823BD2AAB612E696E21A63622BB9A432A2F282911056A228C29B92F:2861f689-4e24-4999-ab97-f0541ba2d288";
    private String ecKidVersion = "042801c0-b7eb-4da9-ac65-f90eda4f02a2";
    private String ecSignature = "MEUCIQC5kfP8fQFVKAjcfLZhmAQ7yLlcRoTUJlwUSmnBuL3n/QIgU9UHpT+audmNmOnmiN79HZI8z4h+h1ijjO1lmOdCHCY=";

    private String payload = "test";
    private String payload_64 = "dGVzdAo=";

    private com.nimbusds.jose.util.Base64URL signature_base64;
    private String ec_public_key;

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
        // EC

        // KID


        // JWT payload   first 2 parts
/*
eyJqa3UiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODA4MFwvLndlbGwta25vd25cL2p3a3MuanNvbiIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0OjgwODAiLCJzdWIiOiJnb3QgbWlsaz8iLCJzY3AiOiJkb2l0IiwiZXhwIjoxNjAyMTkxMTY5fQ

base64:
ZXlKcWEzVWlPaUpvZEhSd09sd3ZYQzlzYjJOaGJHaHZjM1E2T0RBNE1Gd3ZMbmRsYkd3dGEyNXZkMjVjTDJwM2EzTXVhbk52YmlJc0ltRnNaeUk2SWtWVE1qVTJJbjAuZXlKcGMzTWlPaUpvZEhSd2N6cGNMMXd2Ykc5allXeG9iM04wT2pnd09EQWlMQ0p6ZFdJaU9pSm5iM1FnYldsc2F6OGlMQ0p6WTNBaU9pSmtiMmwwSWl3aVpYaHdJam94TmpBeU1Ua3hNVFk1ZlEK
*/


        // SIGNATURE
        // base64 encoded

        // base64 encoded
        String data = Base64.getEncoder().encodeToString(ecSignature.getBytes());
        // Saved as base64
        signature_base64 = new com.nimbusds.jose.util.Base64URL(data);

        System.out.println("");
        System.out.println("signature: ");
        System.out.println(ecSignature);

        System.out.println("");
        System.out.println("signature base64 encoded: ");
        System.out.println(signature_base64);

        // make from parsed string
        ec_public_key =
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEidprkZQXWu+MVdqgETWr6w1SjG3mlGnAbcilJj7lpOat7+6P/QouEWWS1+SeMXFBlP16bs5+Ili0JvYAfMjLRA==";

        java.security.PublicKey publicKey = toECPub(ec_public_key);
/*
        JWK publicJwk = JWK.parseFromPEMEncodedObjects(ec_public_key);
        System.out.println("public JWK output:");
        System.out.println(publicJwk.toJSONObject());

        // Make real JWK, adding the kid as well
        ecJwk = new com.nimbusds.jose.jwk.ECKey.Builder(
            Curve.P_256,
            (ECPublicKey) publicJwk.toECKey().toPublicKey())
                .keyID(ecKid)
                .build();
*/
        ecJwk = new com.nimbusds.jose.jwk.ECKey.Builder(
            Curve.P_256,
                (ECPublicKey) publicKey)
                .keyID(ecKid)
                .build();
        
        System.out.println("ecJwk: " + ecJwk);
        System.out.println("ecJwk: " + ecJwk.toECKey().toPublicKey());
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

    // Make jwk from EC keypair
    private JWK makeEcJwk(KeyPair keyPair) {
        JWK jwk = new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                .privateKey((ECPrivateKey) keyPair.getPrivate())
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

            System.out.println("");
            System.out.println("---------------------");
            System.out.println("expected algorithm: " + expectedJWSAlg);
            System.out.println("expected kid: " + kid);
            System.out.println("key selector: " + keySelector);
            System.out.println(keySelector.getJWKSource());
            System.out.println(keySelector.isAllowed(expectedJWSAlg));
            System.out.println();

            // TEST
            JWKMatcher matcher = new JWKMatcher.Builder().keyID(this.ecKid).build();
            JWKSelector selector = new JWKSelector(matcher);
            JWKSource<SecurityContext> source = keySelector.getJWKSource();
            List<JWK> jwks = source.get(selector, null);
            System.out.println("get JWKs:");
            jwks.forEach(System.out::println);

            JWK first = jwks.get(0);
            java.security.PublicKey publicKey = first.toECKey().toPublicKey();
            // Get java publickey
            System.out.println(publicKey);

            // Verify signature
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initVerify(publicKey);

            // payload is first 2 parts of JWT
            String jwtPayload = "eyJqa3UiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODA4MFwvLndlbGwta25vd25cL2p3a3MuanNvbiIsImtpZCI6IjE6MjpFMDBDQjlCMzU4MjNCRDJBQUI2MTJFNjk2RTIxQTYzNjIyQkI5QTQzMkEyRjI4MjkxMTA1NkEyMjhDMjlCOTJGOjZiODkyNzY4LTQ1NTctNDViMS05MmQ4LTlhMDNmNDY4YzM3ZSIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODA4MCIsInN1YiI6ImdvdCBtaWxrPyIsInNjcCI6ImRvaXRtZW93IiwiZXhwIjoxNjAyMjY3OTM3fQ";

            // base64encoded
            String jwtPayload64 = "ZXlKcWEzVWlPaUpvZEhSd09sd3ZYQzlzYjJOaGJHaHZjM1E2T0RBNE1Gd3ZMbmRsYkd3dGEyNXZkMjVjTDJwM2EzTXVhbk52YmlJc0ltRnNaeUk2SWtWVE1qVTJJbjAuZXlKcGMzTWlPaUpvZEhSd2N6cGNMMXd2Ykc5allXeG9iM04wT2pnd09EQWlMQ0p6ZFdJaU9pSm5iM1FnYldsc2F6OGlMQ0p6WTNBaU9pSmtiMmwwSWl3aVpYaHdJam94TmpBeU1Ua3hNVFk1ZlEK";

//            signer.update(jwyPayload64.getBytes());
            signer.update("foo".getBytes());
//            signer.update(jwyPayload.getBytes());

            byte[] signature = signedJwt.getSignature().decode();
            System.out.println("signedJwt. signature: " + new String(signature));
            boolean verified = signer.verify(signature);

            System.out.println("XXXXXXXXXXXX " + verified);

            System.out.println("end test");
            System.out.println("---------------------");
            // End TEST

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



    ///////////////////////////////////////////////////////////
    // 
    // endpoints
    // 
    ///////////////////////////////////////////////////////////    



    @RequestMapping("/test")
    public String test() throws Exception {
        // payload
        String clear = this.payload;
        String base64 = this.payload_64;
        String signature = ecSignature;
        
        System.out.println("payload: " + base64);
        System.out.println("signature: " + signature);

        PublicKey publicKey = null;
/*
        JWK publicJwk = JWK.parseFromPEMEncodedObjects(ec_public_key);
        System.out.println("public JWK output:");
        System.out.println(publicJwk.toJSONObject());

        // Get public key
        publicKey = publicJwk.toECKey().toPublicKey();
        System.out.println("-------");
        System.out.println("1: " + publicKey);
        System.out.println("-------");
*/

        publicKey = toECPub(ec_public_key);
        System.out.println("-------");
        System.out.println("2: " + publicKey);
        System.out.println("-------");

        // Verify signature
        Signature signer = Signature.getInstance("SHA256withECDSA");
        // initialize with public key
        signer.initVerify(publicKey);

        // update with payload
//        signer.update(clear.getBytes());
        signer.update(base64.getBytes());

        // verify the signature
        boolean verified = signer.verify(Base64.getDecoder().decode(signature.getBytes()));

        System.out.println("Verified? " + verified);

        return "done";
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
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(this.ecKid)
                .jwkURL(new URI(WELL_KNOWN))
                .build();
        // convert to base64url
        com.nimbusds.jose.util.Base64URL header_base64 = header.toBase64URL();


        System.out.println("");
        System.out.println("header");
        System.out.println(header_base64);

        System.out.println("");
        System.out.println("claims/payload:");
        System.out.println(claims_base64);


        // sign with the 3 parts
        SignedJWT signedJWT = new SignedJWT(
            header_base64,
            claims_base64,
            this.signature_base64);

        System.out.println("");
        System.out.println("signature: " + new String(this.signature_base64.decode()));
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

            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initVerify(publicKey);

            // signature is not base64 encoded now
            byte[] signature = this.signature_base64.decode();
            System.out.println("signature: " + new String(signature));
            System.out.println("signature: " + this.signature_base64);

            ///////
            // have signer verify the signature

            // base64 encoded
            String payload64 = "ZXlKcWEzVWlPaUpvZEhSd09sd3ZYQzlzYjJOaGJHaHZjM1E2T0RBNE1Gd3ZMbmRsYkd3dGEyNXZkMjVjTDJwM2EzTXVhbk52YmlJc0ltRnNaeUk2SWtWVE1qVTJJbjAuZXlKcGMzTWlPaUpvZEhSd2N6cGNMMXd2Ykc5allXeG9iM04wT2pnd09EQWlMQ0p6ZFdJaU9pSm5iM1FnYldsc2F6OGlMQ0p6WTNBaU9pSmtiMmwwSWl3aVpYaHdJam94TmpBeU1Ua3hNVFk1ZlEK";

            String payload = "eyJqa3UiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODA4MFwvLndlbGwta25vd25cL2p3a3MuanNvbiIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0OjgwODAiLCJzdWIiOiJnb3QgbWlsaz8iLCJzY3AiOiJkb2l0IiwiZXhwIjoxNjAyMTkxMTY5fQ";

            // From 'foo'
//            payload64 = "Zm9vCg==";
            payload64 = "foo";

            signer.update(payload64.getBytes());

            // test
            boolean verified = signer.verify(Base64.getDecoder().decode(signature));
//            boolean verified = signer.verify(signature);
//            boolean verified = signer.verify(ecSignature.getBytes());

            System.out.println("VERIFY: " + verified);


        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("------------------------------------------");


        return signedJWT.serialize();
    }

    private java.security.PublicKey toECPub(String publicKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return toPub(publicKey, kf);
    }

    private java.security.PublicKey toPub(String publicKey, KeyFactory kf) throws Exception {
//        final String publicKeyContent = getPublicKeyContent(publicKey);
        final String publicKeyContent = publicKey;

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        final java.security.PublicKey pubKey = kf.generatePublic(keySpecX509);
        return pubKey;
    }

    private String getPublicKeyContent(String pub) {
        return pub
                .replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
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
    public Map<String, Object> jwks2() throws Exception {
        List<JWK> keys = new ArrayList<JWK>();
        keys.add(jwk.toPublicJWK());
        keys.add(jwk2.toPublicJWK());
        keys.add(ecJwk.toPublicJWK());

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
    String validateEc(@RequestBody String jwt) throws Exception {
        String result = validateTokenEc(jwt);
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
