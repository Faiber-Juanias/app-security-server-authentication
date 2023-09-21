package com.security.appsecurityserverauthentication.entities;

import jakarta.persistence.*;
import lombok.Data;

import java.util.List;

@Data
@Entity
@Table(name = "customers")
public class CustomerEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String email;
    @Column(name = "pwd")
    private String password;

    @OneToMany(fetch = FetchType.EAGER)
    @JoinColumn(name = "id_customer")
    private List<RoleEntity> roles;

}
