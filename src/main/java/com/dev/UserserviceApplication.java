package com.dev;

import com.dev.domain.AppUser;
import com.dev.domain.Role;
import com.dev.service.AppUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserserviceApplication.class, args);
    }


    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(AppUserService userService){
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveAppUser(new AppUser(null, "José Mateus", "jose", "1234", new ArrayList<>()));
            userService.saveAppUser(new AppUser(null, "Ana Maria", "ana", "1234", new ArrayList<>()));
            userService.saveAppUser(new AppUser(null, "Pedro Costela", "pedro", "1234", new ArrayList<>()));
            userService.saveAppUser(new AppUser(null, "Livia Soares", "livia", "1234", new ArrayList<>()));

            userService.addRoleToAppUser("jose", "ROLE_SUPER_ADMIN");
            userService.addRoleToAppUser("jose", "ROLE_ADMIN");
            userService.addRoleToAppUser("jose", "ROLE_USER");

            userService.addRoleToAppUser("ana", "ROLE_ADMIN");
            userService.addRoleToAppUser("pedro", "ROLE_MANAGER");
            userService.addRoleToAppUser("livia", "ROLE_USER");





        };
    }
}
