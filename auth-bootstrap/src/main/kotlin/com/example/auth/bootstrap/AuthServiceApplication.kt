package com.example.auth.bootstrap

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.domain.EntityScan
import org.springframework.data.jpa.repository.config.EnableJpaRepositories
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication(scanBasePackages = ["com.example.auth"])
@EnableJpaRepositories(basePackages = ["com.example.auth.adapter.out.persistence"])
@EntityScan(basePackages = ["com.example.auth.adapter.out.persistence"])
@EnableScheduling
open class AuthServiceApplication

fun main(args: Array<String>) {
    SpringApplication.run(AuthServiceApplication::class.java, *args)
}
