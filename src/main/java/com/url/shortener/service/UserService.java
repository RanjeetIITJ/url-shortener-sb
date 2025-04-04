package com.url.shortener.service;

import com.url.shortener.dtos.LoginRequest;
import com.url.shortener.models.User;
import com.url.shortener.repository.UserRepository;
import com.url.shortener.security.jwt.JwtAuthenticationResponse;
import com.url.shortener.security.jwt.JwtUtils;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

//    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public User registerUser(User user){
        log.info("Registering user: {}", user.getUsername());
        log.info("Raw Password: {}", user.getPassword());
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        log.debug("Encoded Password: {}", encodedPassword);

        user.setPassword(encodedPassword);
        return userRepository.save(user);
    }


    public JwtAuthenticationResponse authenticateUser(LoginRequest loginRequest){
        log.info("Authenticating user: {}", loginRequest.getUsername());
        log.debug("Entered Password: {}", loginRequest.getPassword());

        Optional<User> optionalUser = userRepository.findByUsername(loginRequest.getUsername());
        if (optionalUser.isEmpty()) {
            log.warn("User not found: {}", loginRequest.getUsername());
            throw new RuntimeException("User not found");
        }

        User user = optionalUser.get(); // Extract the User object safely
        log.debug("Stored Encoded Password: {}", user.getPassword());

        boolean matches = passwordEncoder.matches(loginRequest.getPassword(), user.getPassword());
        log.debug("Password Match: {}", matches);

        if (!matches) {
            throw new RuntimeException("Invalid password");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwt = jwtUtils.generateToken(userDetails);
        return new JwtAuthenticationResponse(jwt);
    }

    public User findByUsername(String name){
        return userRepository.findByUsername(name).orElseThrow(
                ()->new UsernameNotFoundException("User not found with username "+name)
        );
    }
}
