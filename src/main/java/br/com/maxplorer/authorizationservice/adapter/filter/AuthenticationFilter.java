package br.com.maxplorer.authorizationservice.adapter.filter;

import br.com.maxplorer.authorizationservice.core.application.domain.token.Token;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory {

    @Override
    public GatewayFilter apply(Object configuration) {

        return (exchange, chain) -> chain.filter(exchange).then(Mono.fromRunnable(() -> {

            final ServerHttpResponse response = exchange.getResponse();

            if (HttpStatus.NO_CONTENT.equals(response.getStatusCode())) {

                final Token token = Token.newToken("userId");

                exchange.getResponse().getHeaders().add("Token", token.token());
                exchange.getResponse().getHeaders().add("Refresh-Token", token.refreshToken());
            }
        }));
    }
}
