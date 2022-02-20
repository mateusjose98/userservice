package com.dev.service;

import com.dev.domain.AppUser;
import com.dev.domain.Role;
import com.dev.repository.AppUserRepository;
import com.dev.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service @RequiredArgsConstructor @Transactional @Slf4j
public class AppUserServiceImpl implements  AppUserService, UserDetailsService {

    private final AppUserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        AppUser user = userRepo.findByUsername(username);
        if(user == null) throw new UsernameNotFoundException("Usuário não encontrado!");

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role ->  authorities.add(new SimpleGrantedAuthority(role.getName())));

        return new User(user.getUsername(), user.getPassword(), authorities);
    }

    @Override
    public AppUser saveAppUser(AppUser user) {
        log.info("Saving new user");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role");
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToAppUser(String username, String roleName) {
        log.info("add Role To AppUser");
        AppUser user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);

    }

    @Override
    public AppUser getUser(String username) {
        log.info("searching user by username");
        return userRepo.findByUsername(username);
    }

    @Override
    public List<AppUser> getAppUsers() {
        log.info("fetching all users");
        return userRepo.findAll();
    }


}
