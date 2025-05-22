package io.gateway_service.filters; // Or wherever your filters reside

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

// Don't forget to implement the actual logging logic in the apply method!
@Component
public class GlobalLoggingFilterFactory extends AbstractGatewayFilterFactory<GlobalLoggingFilterFactory.Config> {

    private static final Logger logger = LoggerFactory.getLogger(GlobalLoggingFilterFactory.class);

    public GlobalLoggingFilterFactory() {
        super(Config.class); // Specify the configuration class
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // Pre-request logging
            logger.info("Incoming request: {} {} from {}",
                    exchange.getRequest().getMethod(),
                    exchange.getRequest().getURI(),
                    exchange.getRequest().getRemoteAddress());

            long startTime = System.currentTimeMillis();

            // Continue the filter chain
            return chain.filter(exchange)
                    .then(Mono.fromRunnable(() -> {
                        // Post-request logging
                        long endTime = System.currentTimeMillis();
                        long duration = endTime - startTime;
                        logger.info("Outgoing response for request {}: Status {} (duration: {}ms)",
                                exchange.getRequest().getURI(),
                                exchange.getResponse().getStatusCode(),
                                duration);
                    }));
        };
    }

    // A simple Config class if your filter doesn't need arguments from application.yml
    public static class Config {
        // No specific configuration properties needed for a basic global logging filter
    }
}