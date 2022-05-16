package com.github.TheTrueHooha.OAuth.Security.Implementation.Services;

import com.github.TheTrueHooha.OAuth.Security.Implementation.Model.Users;
import com.github.TheTrueHooha.OAuth.Security.Implementation.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@Transactional

public class UserServices implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Users user = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("username not found in the registry");
        }
        return new User(
                user.getEmail(),
                user.getPassword(),
                user.getIsEnabled(),
                true,
                true,
                true,
                getAuthorities(List.of(user.getRole()))
        );
    }

    private Collection<? extends GrantedAuthority> getAuthorities(List<String> roles) {
    List<GrantedAuthority> authority = new ArrayList<>();
    for (String role : roles) {
        authority.add(new SimpleGrantedAuthority(role));
        }
    return authority;
    }
}
