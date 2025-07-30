package io.woyyd.frodo.api.authentication

import org.springframework.http.MediaType
import org.springframework.web.client.RestClient
import org.springframework.web.client.toEntity
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class AuthenticationService {

    private val restClient = RestClient.builder().build()

    fun <K, V> MutableMap<K, V>.toUrlEncodedFormBody(): String {
        return this.map {
            val key = URLEncoder.encode(it.key.toString(), StandardCharsets.UTF_8)
            val value = URLEncoder.encode(it.value.toString(), StandardCharsets.UTF_8)
            "$key=$value"
        }.joinToString("&")
    }

    fun authenticateSteamUser(parameterMap: Map<String, Array<String>>): String {
        val x =
            parameterMap
                .filter { it.key.startsWith("openid") } //get only OpenID parameters
                .mapValues { it.value.first() } // arrays not needed, take first value
                .toMutableMap()
                .also { it.put("openid.mode", "check_authentication") }
                .toUrlEncodedFormBody()
        if (validateSteam(x)) {
            val steamId = parameterMap["openid.claimed_id"]?.first()?.substringAfterLast("/id/") ?: throw IllegalArgumentException("Steam ID not found in response")
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
}