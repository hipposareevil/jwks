package com.wpff.grpc;

import com.nimbusds.jwt.SignedJWT;
import com.salesforce.einstein.hawking.auth.grpc.jwt.C2CExchangeRequest;
import com.salesforce.einstein.hawking.auth.grpc.jwt.C2CExchangeResponse;
import com.salesforce.einstein.hawking.auth.grpc.jwt.JwtExchangeGrpc;
import com.wpff.jwt.JwtUtil;
import io.grpc.stub.StreamObserver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Signed;

@Component
public class JwtExchange extends JwtExchangeGrpc.JwtExchangeImplBase {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public void exchangeC2CForJwt(C2CExchangeRequest request,
                                  StreamObserver<C2CExchangeResponse> responseObserver) {
        String newJwt = "super.jwt.here";
        String c2cJwt = request.getToken();

        System.out.println("Exchanging '" + c2cJwt + "' for '" + newJwt + "'");
        
        // Create bogus JWT
        String scope=c2cJwt;
        try {
            SignedJWT jwt = this.jwtUtil.createJwt(scope);
            newJwt = jwt.serialize();
        } catch (Exception e) {
            e.printStackTrace();
            newJwt = "error: "+ e.getMessage();
        }

        C2CExchangeResponse reply = C2CExchangeResponse
                .newBuilder()
                .setToken(newJwt)
                .build();
           responseObserver.onNext(reply);
      responseObserver.onCompleted();
    }
}
