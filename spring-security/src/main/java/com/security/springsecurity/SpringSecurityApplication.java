
// Spring Security Application Anuka-Rathnayake 2023-02-13

package com.security.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
		System.out.print("<--------------------------------------->");
		System.out.print("Spring Security App is Running !!!!!!!!! ");
		System.out.print("<--------------------------------------->");
	}

}
