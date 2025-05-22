package io.gateway_service.filters;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.http.HttpStatus; // For potential error handling

@Component // Make this a Spring bean
public class TenantIdPropagatorFilterFactory extends AbstractGatewayFilterFactory<TenantIdPropagatorFilterFactory.Config> {

    public TenantIdPropagatorFilterFactory() {
        super(Config.class); // Specify the configuration class
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) ->
                ReactiveSecurityContextHolder.getContext()
                        .map(SecurityContext::getAuthentication)
                        .filter(auth -> auth instanceof JwtAuthenticationToken)
                        .cast(JwtAuthenticationToken.class)
                        .map(JwtAuthenticationToken::getPrincipal)
                        .cast(Jwt.class)
                        .flatMap(jwt -> {
                            String tenantId = jwt.getClaimAsString("tenantId");
                            if (tenantId != null) {
                                ServerWebExchange mutated = exchange.mutate()
                                        .request(r -> r.header("X-Tenant-Id", tenantId))
                                        .build();
                                return chain.filter(mutated);
                            }
                            return chain.filter(exchange);
                        })
                        /* ── NEW: if no security context (e.g. /auth/login) just continue ── */
                        .switchIfEmpty(chain.filter(exchange));
    }

    // You can define inner static Config class if your filter needs arguments from application.yml
    public static class Config {
        // No specific config properties needed for TenantIdPropagatorFilter currently
        // But if you had arguments like 'headerName: X-My-Tenant-ID', they'd go here.
    }
}