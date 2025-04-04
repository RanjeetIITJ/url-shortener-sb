package com.url.shortener.service;

import com.url.shortener.dtos.LoginRequest;
import com.url.shortener.models.User;
import com.url.shortener.repository.UserRepository;
import com.url.shortener.security.jwt.JwtAuthenticationResponse;
import com.url.shortener.security.jwt.JwtUtils;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
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
public class UserService {

//    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public User registerUser(User user){
        System.out.println("Registering user: " + user.getUsername());
        System.out.println("Raw Password: " + user.getPassword());

        String encodedPassword = passwordEncoder.encode(user.getPassword());
        System.out.println("Encoded Password: " + encodedPassword);

        user.setPassword(encodedPassword);
        return userRepository.save(user);
    }

//    public JwtAuthenticationResponse authenticateUser(LoginRequest loginRequest) {
//        System.out.println("Authenticating user: " + loginRequest.getUsername());
//
//        Authentication authentication;
//        try {
//            authentication = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(
//                            loginRequest.getUsername(),
//                            loginRequest.getPassword()
//                    )
//            );
//        } catch (Exception e) {
//            System.out.println("Authentication failed: " + e.getMessage());
//            throw new RuntimeException("Invalid username or password");
//        }
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//
//        String jwt = jwtUtils.generateToken(userDetails);
//        return new JwtAuthenticationResponse(jwt);
//    }

    public JwtAuthenticationResponse authenticateUser(LoginRequest loginRequest){
        System.out.println("Authenticating user: " + loginRequest.getUsername());
        System.out.println("Entered Password: " + loginRequest.getPassword());

        Optional<User> optionalUser = userRepository.findByUsername(loginRequest.getUsername());
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("User not found");
        }

        User user = optionalUser.get(); // Extract the User object safely
        System.out.println("Stored Encoded Password: " + user.getPassword());

        boolean matches = passwordEncoder.matches(loginRequest.getPassword(), user.getPassword());
        System.out.println("Password Match: " + matches);

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
