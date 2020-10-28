package com.wpff.jwks;

import java.util.Arrays;

import com.wpff.grpc.GrpcServer;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Application {

	public static void main(String[] args) throws Exception {
		System.out.println("Start Spring");
		SpringApplication.run(Application.class, args);
		System.out.println("Started  Spring");

		System.out.println("");
		System.out.println("Start grpc");
		final GrpcServer server = new GrpcServer();
		server.start();
		server.blockUntilShutdown();



	}

}
