package io.woyyd.frodo.api.authentication

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.woyyd.frodo.api.TokenResponseDto
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
import java.time.OffsetDateTime
import java.util.Date
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

@RestController
class SteamController(private val authenticationService: AuthenticationService, @Value("\${CALLBACK_URL}") private val callbackUrl: String) {

    val logger = LoggerFactory.getLogger(this::class.java)

    @GetMapping("/auth/steam")
    @Throws(IOException::class)
    fun redirectToSteam(response: HttpServletResponse) {
        val returnTo: String? = URLEncoder.encode("$callbackUrl/auth/steam/callback", StandardCharsets.UTF_8)
        val steamLoginUrl = ("https://steamcommunity.com/openid/login"
                + "?openid.ns=http://specs.openid.net/auth/2.0"
                + "&openid.mode=checkid_setup"
                + "&openid.return_to=" + returnTo
                + "&openid.realm=$callbackUrl"
                + "&openid.identity=http://specs.openid.net/auth/2.0/identifier_select"
                + "&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select")

        response.sendRedirect(steamLoginUrl)
    }


    @GetMapping("/auth/steam/callback")
    @Throws(Exception::class)
    fun handleSteamCallback(request: HttpServletRequest): ResponseEntity<TokenResponseDto> {
        try {
            val authenticateSteamUser = authenticationService.authenticateSteamUser(request.parameterMap)
            val issuedAt = OffsetDateTime.now()
            val tokenDuration = 60.minutes
            val jwt = authenticationService.createJwt(authenticateSteamUser, issuedAt, tokenDuration)
            TokenResponseDto(jwt, issuedAt.plusMinutes(tokenDuration.inWholeMinutes)).also {
                logger.info("Steam authentication successful for user: $authenticateSteamUser")
            }.let { tokenResponse ->
                return ResponseEntity.ok(tokenResponse)
            }
        } catch (e: IllegalArgumentException) {
            logger.error("Steam authentication failed: ${e.message}")
            return ResponseEntity.badRequest().build()
        }
    }
}