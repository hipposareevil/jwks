package com.wpff.jwks;

import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.salesforce.sds.kms.client.kmsOpenAPIJavaClient.model.SmsSignature;
import jdk.internal.jimage.ImageLocation;
import org.spongycastle.openssl.PEMWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;


import java.io.StringWriter;
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

    @Value("${host}")
    private String host;

    // 'aud' JWT scope.
    // This is who the JWT is intended for.
    private String AUDIENCE = "com.foundation.auth";

    // Interact with kms service
    private KeyServiceClient keyClient = KeyServiceClient.getClient();

    // Contains public + private 
    private final KeyPair rsaKeyPair;
    private final KeyPair rsaKeyPair2;

    private final JWK jwk;
    private final JWK jwk2;

    // elliptic curve, created with KMS public key
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

        // Make RSA JWKs
        jwk = makeRsaJwk(rsaKeyPair);
        jwk2 = makeRsaJwk(rsaKeyPair2);

        //////////////
        // elliptic curve, created from KMS public key
        ecJwk = makeEcJwk();
    }


    /**
     * Make a RSA JWK from incoming keypair
     *
     * @param keyPair
     * @return
     */
    private JWK makeRsaJwk(KeyPair keyPair) {
        JWK jwk = new com.nimbusds.jose.jwk.RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .build();

        return jwk;
    }

    /**
     * Make an EC JWK that will be used to create JWTs.
     * This is created with public key from KMS.
     *
     * @return elliptical curve JWK
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


    /**
     * Validate incoming JWT
     * @param jwtString JWT as string
     * @return output of validation
     * @throws Exception
     */
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
                    new JWTClaimsSet.Builder().issuer(this.host).build(),
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

    // Create elliptical curve JWT
    @RequestMapping("/ec/gotJwt")
    public String gotJwtEC_base(@RequestParam String scope) throws Exception {
        String well_known_uri = this.host + "/.well-known/jwks.json";
        System.out.println("URI: " + well_known_uri);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got beer?")
                .issuer(this.host)
                .claim("scp",  scope)
                .audience(AUDIENCE)
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        // Create the EC signer
        JWSSigner signer = new ECDSASigner(this.keyClient.getPrivateKey());
        String kid = this.ecJwk.getKeyID();

        // Make new JWT with
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(kid)
                        //.jwk(this.ecJwk)
                        .jwkURL(new URI(well_known_uri))
                        .build(),
                claimsSet);

        // Compute the EC signature
        signedJWT.sign(signer);

        String base64signature = signedJWT.getSignature().toString();
        System.out.println("base64 signature: " + base64signature);

        // Serialize the JWS to compact form
        String s = signedJWT.serialize();

        return s;
    }


    // Create JWT
    @RequestMapping("/rsa/gotJwt")
    public String gotJwt(@RequestParam String scope) throws Exception {
        System.out.println("-------");
        System.out.println("gotJwt");

        String well_known_uri = this.host + "/.well-known/jwks.json";
        System.out.println("URI: " + well_known_uri);

        // Get privatekey and kid
        String kid = jwk.getKeyID();
        PrivateKey privateKey = rsaKeyPair.getPrivate();


        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(privateKey);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("got milk?")
                .claim("scp", scope)
                .issuer(this.host)
                .audience(AUDIENCE)
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(kid)
                        .jwkURL(new URI(well_known_uri))
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

        JWKSet set = new JWKSet(keys);
        return set.toJSONObject(true);
    }


    // Validate jwt
    @PostMapping("/validate")
    String validate(@RequestBody JwtData jwt) throws Exception {
        System.out.println("VALIDATE EC");
        System.out.println(jwt.data);
        String result = validateToken(jwt.data);
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
