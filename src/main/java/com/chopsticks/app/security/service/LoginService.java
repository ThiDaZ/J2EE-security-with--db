package com.chopsticks.app.security.service;

import com.chopsticks.app.security.model.User;
import jakarta.enterprise.context.RequestScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import java.util.Set;

@RequestScoped
public class LoginService {

    @PersistenceContext
    private EntityManager em;

    public boolean validate(String username, String password) {
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            return false;
        }
        User user = em.find(User.class, username);
        return user != null && user.getPassword().equals(password);
    }

    public Set<String> getRoles(String username){
        if (username == null || username.isEmpty()) {
            return Set.of();
        }
        User user = em.find(User.class, username);
        return user != null ? user.getRoles() : Set.of();
    }

    public User getUser(String username){
        if (username == null || username.isEmpty()) {
            return null;
        }
        return em.find(User.class, username);
    }

}
