package dev.cosmingherghe.sbs.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping("/profile")
public class ProfileController {

    @GetMapping("/")
    public String index() {return "/profile/index";}
}
