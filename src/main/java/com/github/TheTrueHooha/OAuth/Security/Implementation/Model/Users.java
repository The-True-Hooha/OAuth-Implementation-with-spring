package com.github.TheTrueHooha.OAuth.Security.Implementation.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity

public class Users {

    @Id @GeneratedValue (strategy = GenerationType.AUTO)
    private Long id;

    private String name;

    private String email;

    private String location;

    @Column (length = 40)
    private String password;

    private String gender;

    private String role;

    private Boolean isEnabled = false;
}
