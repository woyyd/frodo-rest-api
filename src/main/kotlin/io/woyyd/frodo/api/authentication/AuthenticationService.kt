package io.woyyd.frodo.api.authentication

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.web.client.RestClient
import org.springframework.web.client.toEntity
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.OffsetDateTime
import java.util.Date
import kotlin.time.Duration

@Service
class AuthenticationService(@Value("\${jwt.secret}") private val jwtSecret: String, @Value("\${ALLOWED_STEAM_IDS}") tempSteamIds: String) {

    private val allowedSteamIds: Set<String> = tempSteamIds.split(",").map { it.trim() }.toSet()

    private val restClient = RestClient.builder().build()

    fun <K, V> MutableMap<K, V>.toUrlEncodedFormBody(): String {
        return this.map {
            val key = URLEncoder.encode(it.key.toString(), StandardCharsets.UTF_8)
            val value = URLEncoder.encode(it.value.toString(), StandardCharsets.UTF_8)
            "$key=$value"
        }.joinToString("&")
    }

    fun OffsetDateTime.toDate(): Date {
        return Date.from(this.toInstant())
    }

    fun authenticateSteamUser(parameterMap: Map<String, Array<String>>): String {
        val steamId = parameterMap["openid.claimed_id"]?.first()?.substringAfterLast("/id/") ?: throw IllegalArgumentException("Steam ID not found in response")
        if (steamId !in allowedSteamIds) {
            throw IllegalArgumentException("Steam ID $steamId is not allowed")
        }
        val x =
            parameterMap
                .filter { it.key.startsWith("openid") } //get only OpenID parameters
                .mapValues { it.value.first() } // arrays not needed, take first value
                .toMutableMap()
                .also { it.put("openid.mode", "check_authentication") }
                .toUrlEncodedFormBody()
        if (validateSteam(x)) {
            return steamId
        }
        throw IllegalArgumentException("Invalid Steam authentication response")
    }

    private fun validateSteam(formBody: String): Boolean {
        val res = restClient.post().uri("https://steamcommunity.com/openid/login")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(formBody).retrieve().toEntity<String>()
        return res.body?.contains("is_valid:true") ?: false
    }

    fun createJwt(steamId: String, issuedAt: OffsetDateTime, tokenDuration : Duration): String {
        return Jwts.builder()
            .setSubject(steamId)
            .setIssuedAt(issuedAt.toDate())
            .setExpiration(issuedAt.plusSeconds(tokenDuration.inWholeSeconds).toDate())
            .signWith(SignatureAlgorithm.HS256, jwtSecret.toByteArray())
            .compact()

    }
}