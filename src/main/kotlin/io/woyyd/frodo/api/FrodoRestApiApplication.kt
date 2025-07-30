package io.woyyd.frodo.api

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class FrodoRestApiApplication

fun main(args: Array<String>) {
	runApplication<FrodoRestApiApplication>(*args)
}
