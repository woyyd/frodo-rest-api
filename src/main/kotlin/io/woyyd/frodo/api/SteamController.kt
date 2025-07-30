package io.woyyd.frodo.api

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestClient
import org.springframework.web.client.toEntity
import java.io.IOException
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.*


@RestController
class SteamController(@Value("\${jwt.secret}") private val jwtSecret: String) {

    val logger = LoggerFactory.getLogger(this::class.java)

    @GetMapping("/auth/steam")
    @Throws(IOException::class)
    fun redirectToSteam(response: HttpServletResponse) {
        val returnTo: String? = URLEncoder.encode("http://localhost:8080/auth/steam/callback", StandardCharsets.UTF_8)
        val steamLoginUrl = ("https://steamcommunity.com/openid/login"
                + "?openid.ns=http://specs.openid.net/auth/2.0"
                + "&openid.mode=checkid_setup"
                + "&openid.return_to=" + returnTo
                + "&openid.realm=http://localhost:8080"
                + "&openid.identity=http://specs.openid.net/auth/2.0/identifier_select"
                + "&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select")

        response.sendRedirect(steamLoginUrl)
    }


    @GetMapping("/auth/steam/callback")
    @Throws(Exception::class)
    fun handleSteamCallback(request: HttpServletRequest): ResponseEntity<String?> {

        val x =
            request.parameterMap.filter { it.key.startsWith("openid") }.mapValues { it.value.first() }.toMutableMap()
        x.put("openid.mode", "check_authentication")
        val z = x.map {
            "${URLEncoder.encode(it.key, StandardCharsets.UTF_8)}=${
                URLEncoder.encode(
                    it.value,
                    StandardCharsets.UTF_8
                )
            }"
        }.joinToString("&")
        val y = RestClient.builder().build()

        val res =
            y.post().uri("https://steamcommunity.com/openid/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(z).retrieve().toEntity<String>()

        if (res.body?.contains("is_valid:true") ?: false) {
            val steamId = request.getParameter("openid.claimed_id")?.substringAfterLast("/id/")
            if (steamId != null) {
                val jwt = Jwts.builder()
                    .setSubject(steamId)
                    .setIssuedAt(Date())
                    .setExpiration(Date(System.currentTimeMillis() + 3600_000)) // 1 hour
                    .signWith(SignatureAlgorithm.HS256, jwtSecret.toByteArray())
                    .compact()

                return ResponseEntity.ok(jwt.toString())
            } else {
                return ResponseEntity.status(401).body("Steam ID not found in response")
            }
        }

        return ResponseEntity.ok<String?>("Authenticated as: ")
    }
}