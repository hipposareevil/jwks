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

    public static int COUNT = 0;

    // Contains public + private 
    private final KeyPair rsaKeyPair;
    private final KeyPair rsaKeyPair2;
//    private final KeyPair ecKeyPair;

    private final JWK jwk;
    private final JWK jwk2;
//    private final JWK ecJwk;
    private JWK ecJwk;


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

        // Eliptical Curve
/*
        gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(Curve.P_256.toECParameterSpec());
        ecKeyPair = gen.generateKeyPair();
*/

        // Make JWKs
        jwk = makeRsaJwk(rsaKeyPair);
        jwk2 = makeRsaJwk(rsaKeyPair2);
//        ecJwk = makeEcJwk(ecKeyPair);
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


    // Validate
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
            JWSKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

            System.out.println("expcted: " + expectedJWSAlg);

            jwtProcessor.setJWSKeySelector(keySelector);

            // Set the required JWT claims for access tokens issued by the Connect2id
            // server, may differ with other servers
            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                    new JWTClaimsSet.Builder().issuer("https://localhost:8080").build(),
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

        return "n/a/";
    }

    ///////////////////////////////////////////////////////////
    // 
    // endpoints
    // 
    ///////////////////////////////////////////////////////////    



    // Create JWT
    @RequestMapping("/gotJwtEC")
    public String gotJwtEC(@RequestParam String scope) throws Exception {
        // Get privatekey and kid
/*
        String kid = ecJwk.getKeyID();
        PrivateKey privateKey = ecKeyPair.getPrivate();
*/
        String kid = "1:2:E00CB9B35823BD2AAB612E696E21A63622BB9A432A2F282911056A228C29B92F:6b892768-4557-45b1-92d8-9a03f468c37e";

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got milk?")
                .claim("scp", scope)
                .issuer("https://localhost:8080")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        com.nimbusds.jose.util.Base64URL claims_base64 = new Payload(claimsSet.toJSONObject())
                .toBase64URL();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(kid)
                .jwkURL(new URI("http://localhost:8080/.well-known/jwks.json"))
                .build();
        com.nimbusds.jose.util.Base64URL header_base64 = header.toBase64URL();

        System.out.println("header");
        System.out.println(header_base64);

        System.out.println("claims/payload:");
        System.out.println(claims_base64);

        String signature = "TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFNzZIUmRmaXp1RUM0QWMyZWsyenFreTF0R2NtYwpuMGl6Y2lnd3FXM1VVUHdyMHNFTU8wdlo3QUNybklObmJ5UFJpNW5CbHZoNnNOekVJR0lRUnlGMFFnPT0K";
        com.nimbusds.jose.util.Base64URL signature_base64 = new
                com.nimbusds.jose.util.Base64URL(signature);

        // public
//        String public_key = "TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFNzZIUmRmaXp1RUM0QWMyZWsyenFreTF0R2NtYwpuMGl6Y2lnd3FXM1VVUHdyMHNFTU8wdlo3QUNybklObmJ5UFJpNW5CbHZoNnNOekVJR0lRUnlGMFFnPT0K";
        String public_key = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE76HRdfizuEC4Ac2ek2zqky1tGcmc\nn0izcigwqW3UUPwr0sEMO0vZ7ACrnINnbyPRi5nBlvh6sNzEIGIQRyF0Qg==\n-----END PUBLIC KEY-----";

        JWK publicJwk = JWK.parseFromPEMEncodedObjects(public_key);
        ecJwk = publicJwk;

        System.out.println(publicJwk.toJSONObject());
        System.out.println(publicJwk.toJSONString());


        JWK publicJwktwo = new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_256,
                                                                   (ECPublicKey) publicJwk.toECKey().toPublicKey()
                                                                   )
                .keyID(kid)
                .build();

        ecJwk = publicJwktwo;

//{"kty":"EC","crv":"P-256","x":"76HRdfizuEC4Ac2ek2zqky1tGcmcn0izcigwqW3UUPw","y":"K9LBDDtL2ewAq5yDZ28j0YuZwZb4erDcxCBiEEchdEI"}


        // signed
        SignedJWT signedJWT = new SignedJWT(
            header_base64,
            claims_base64,
            signature_base64);

        String s = signedJWT.serialize();
        return s;
    }


    // Create JWT
    @RequestMapping("/gotJwt")
    public String gotJwt(@RequestParam String scope) throws Exception {
        // Get privatekey and kid
        String kid = jwk.getKeyID();
        PrivateKey privateKey = rsaKeyPair.getPrivate();


        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(privateKey);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got milk?")
                .claim("scp", scope)
                .issuer("https://localhost:8080")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(kid)
                        .jwkURL(new URI("http://localhost:8080/.well-known/jwks.json"))
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
    @PostMapping("/validate")
    String validate(@RequestBody String jwt) throws Exception {
        String result = validateToken(jwt);
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
