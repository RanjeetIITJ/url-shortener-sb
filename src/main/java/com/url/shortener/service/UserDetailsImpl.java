package com.url.shortener.service;

import com.url.shortener.models.User;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Data
@NoArgsConstructor
public class UserDetailsImpl implements UserDetails {

    private static final long serialVersionUID = 1L;
    private Long id;
    private String username;
    private String email;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(Long id, String username, String password, String email, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.authorities = authorities;
    }

    public static UserDetailsImpl build(User user) {
        GrantedAuthority authority = new SimpleGrantedAuthority(
                user.getRole() != null ? user.getRole() : "ROLE_USER" // Default to ROLE_USER if null
        );

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getPassword(),  //  Correct order
                user.getEmail(),
                Collections.singletonList(authority)
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities != null ? authorities : Collections.emptyList(); //  Ensure authorities is never null
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;  //  Ensure account is not expired
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;  //  Ensure account is not locked
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;  //  Ensure credentials are not expired
    }

    @Override
    public boolean isEnabled() {
        return true;  //  Ensure account is enabled
    }
}