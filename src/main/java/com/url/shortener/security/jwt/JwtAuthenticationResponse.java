package com.url.shortener.security.jwt;

import lombok.*;

@Getter@Setter
public class JwtAuthenticationResponse {
    private String token;


    public JwtAuthenticationResponse(){

    }
    public JwtAuthenticationResponse(String token){
        this.token = token;
    }


}
