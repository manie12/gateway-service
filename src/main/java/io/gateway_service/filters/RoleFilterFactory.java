package io.gateway_service.filters;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class RoleFilterFactory extends AbstractGatewayFilterFactory<RoleFilterFactory.Config> {

    public RoleFilterFactory() {
        super(Config.class);
    }

    public static class Config {
        public List<String> roles = new ArrayList<>();

        public Config() {
        }
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            /* ──➊  If no roles declared for this route, just continue ─────────── */
            if (config.roles == null || config.roles.isEmpty()) {
                return chain.filter(exchange);                // ← no-op
            }

            /* ──➋  Normal role-enforcement path ──────────────────────────────── */
            return ReactiveSecurityContextHolder.getContext()
                    .map(SecurityContext::getAuthentication)
                    .filter(auth -> auth instanceof JwtAuthenticationToken)
                    .cast(JwtAuthenticationToken.class)
                    .map(JwtAuthenticationToken::getPrincipal)
                    .cast(Jwt.class)
                    .flatMap(jwt -> {
                        List<String> userRoles = getAllRolesFromJwt(jwt);
                        boolean allowed = userRoles != null &&
                                config.roles.stream().anyMatch(userRoles::contains);

                        if (allowed) {
                            return chain.filter(exchange);
                        }
                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        return exchange.getResponse().setComplete();
                    });
            /* ──➌  No SecurityContext → 401 ──────────────────────────── */

        };
    }

    // Suppress the unchecked warning for this method
    @SuppressWarnings("unchecked")
    private List<String> getAllRolesFromJwt(Jwt jwt) {
        Stream<String> realmRolesStream = Stream.empty();
        Stream<String> resourceRolesStream = Stream.empty();

        // Extract Realm Roles
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            Object rolesObject = realmAccess.get("roles");
            if (rolesObject instanceof List<?> rawList) {
                realmRolesStream = rawList.stream()
                        .filter(Objects::nonNull)
                        .filter(String.class::isInstance)
                        .map(String.class::cast);
            }
        }

        // Extract Resource Access Roles
        Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
        if (resourceAccess != null) {
            resourceRolesStream = resourceAccess.values().stream()
                    .filter(Objects::nonNull)
                    .filter(Map.class::isInstance)
                    // The cast here is the source of the unchecked warning,
                    // which is now suppressed by the method-level annotation.
                    .map(item -> (Map<String, Object>) item)
                    .filter(resourceMap -> resourceMap.containsKey("roles"))
                    .map(resourceMap -> resourceMap.get("roles"))
                    .filter(Objects::nonNull)
                    .filter(List.class::isInstance)
                    .map(item -> (List<?>) item)
                    .flatMap(List::stream)
                    .filter(Objects::nonNull)
                    .filter(String.class::isInstance)
                    .map(String.class::cast);
        }

        // Combine and return distinct roles
        return Stream.concat(realmRolesStream, resourceRolesStream)
                .distinct()
                .collect(Collectors.toList());
    }
}