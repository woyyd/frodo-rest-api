package io.woyyd.frodo.api

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class AuthenticatedController {

    @GetMapping("/test")
    fun test(): String {
        return "Authenticated endpoint reached!"
    }
}