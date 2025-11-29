package com.acai.pay.service;

import com.acaipay.dto.AuthResponse;
import com.acaipay.dto.LoginRequest;
import com.acaipay.dto.RegisterRequest;
import com.acaipay.model.User;
import com.acaipay.repository.UserRepository;
import com.acaipay.security.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    public AuthResponse register(RegisterRequest request) {
        // Verificar se email já existe
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }
        
        // Criar novo usuário
        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setPhone(request.getPhone());
        
        User savedUser = userRepository.save(user);
        
        // Gerar token JWT
        String jwtToken = jwtService.generateToken(savedUser);
        
        return new AuthResponse(jwtToken, savedUser.getId(), savedUser.getEmail(), savedUser.getName());
    }
    
    public AuthResponse login(LoginRequest request) {
        // Autenticar usuário
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        User user = (User) authentication.getPrincipal();
        String jwtToken = jwtService.generateToken(user);
        
        return new AuthResponse(jwtToken, user.getId(), user.getEmail(), user.getName());
    }
}