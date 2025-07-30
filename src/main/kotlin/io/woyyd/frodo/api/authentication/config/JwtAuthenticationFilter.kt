package io.woyyd.frodo.api.authentication.config

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter

class JwtAuthenticationFilter(
    private val jwtSecret: String
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val header = request.getHeader("Authorization")
        if (header != null && header.startsWith("Bearer ")) {
            val token = header.substring(7)

            try {
                val claims = Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(jwtSecret.toByteArray())).build()
                    .parseSignedClaims(token)
                    .payload

                val steamId = claims.subject
                val auth = UsernamePasswordAuthenticationToken(
                    steamId, null, listOf(SimpleGrantedAuthority("ROLE_USER"))
                )
                SecurityContextHolder.getContext().authentication = auth

            } catch (ex: Exception) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token")
                ex.printStackTrace()
                return
            }
        }

        filterChain.doFilter(request, response)
    }
}
