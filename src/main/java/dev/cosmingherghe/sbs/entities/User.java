package dev.cosmingherghe.sbs.entities;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    private int active;

    private String roles = "";

    private String permisions = "";

    public User() {}

    public User(String username, String password, String roles, String permisions) {
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.permisions = permisions;
        this.active = 1;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getActive() {
        return active;
    }

    public void setActive(int active) {
        this.active = active;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public String getPermisions() {
        return permisions;
    }

    public void setPermisions(String permisions) {
        this.permisions = permisions;
    }

    public List<String> getRolesList() {
        if(this.roles.length() > 0) {
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }

    public List<String> getPermisionsList() {
        if(this.permisions.length() > 0) {
            return Arrays.asList(this.permisions.split(","));
        }
        return new ArrayList<>();
    }
}
