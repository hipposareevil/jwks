package com.wpff.endpoints;

import com.wpff.jwt.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;


import java.util.*;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.*;

@RestController
public class JwtController {

    @Autowired
    private JwtUtil jwtUtil;

    // Create elliptical curve JWT
    @RequestMapping("/gotJwt")
    public String gotJwtEC_base(@RequestParam String scope) throws Exception {
        // Create signed JWT
        SignedJWT signedJWT = this.jwtUtil.createJwt(scope);

        // Serialize the JWS to compact form
        String s = signedJWT.serialize();

        // return as sgring
        return s;
    }

    // JWKS!
    @RequestMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() throws Exception {
        List<JWK> keys = new ArrayList<JWK>();
        keys.add(this.jwtUtil.getJWK().toPublicJWK());

        JWKSet set = new JWKSet(keys);
        return set.toJSONObject(true);
    }


    // Validate jwt
    @PostMapping("/validate")
    String validate(@RequestBody JwtData jwt) throws Exception {
        System.out.println("VALIDATE EC");
        System.out.println(jwt.data);
        String result = this.jwtUtil.validateToken(jwt.data);
        return result;
    }

}
