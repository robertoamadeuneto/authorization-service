package br.com.maxplorer.authorizationservice.adapter.filter;

import br.com.maxplorer.authorizationservice.adapter.exception.UnauthorizedException;
import br.com.maxplorer.authorizationservice.core.application.domain.token.Token;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationFilter extends AbstractGatewayFilterFactory {

    @Override
    public GatewayFilter apply(Object config) {

        return (exchange, chain) -> {

            final ServerHttpRequest request = exchange.getRequest();

            if ((request.getHeaders().get(Token.TOKEN_HEADER) == null)
                    || (request.getHeaders().get(Token.TOKEN_HEADER) != null
                    && !request.getHeaders().get(Token.TOKEN_HEADER).get(0).startsWith(Token.TOKEN_PREFIX))
                    || (!Token.isTokenValid(request.getHeaders().get(Token.TOKEN_HEADER).get(0)))) {
                throw new UnauthorizedException();
            }

            return chain.filter(exchange);
        };
    }
}
