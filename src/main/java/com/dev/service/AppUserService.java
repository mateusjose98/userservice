package com.dev.service;

import com.dev.domain.AppUser;
import com.dev.domain.Role;

import java.util.List;


public interface AppUserService {
    AppUser saveAppUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToAppUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getAppUsers();
}
