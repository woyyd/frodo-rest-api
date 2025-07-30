package io.woyyd.frodo.api

import java.time.OffsetDateTime

data class TokenResponseDto(val token: String, val expiry: OffsetDateTime)