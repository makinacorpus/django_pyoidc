FROM quay.io/keycloak/keycloak:20.0.3 as builder

ENV KC_FEATURES=token-exchange,impersonation
ENV KC_HTTP_ENABLED=true
ENV KC_HTTP_RELATIVE_PATH=/auth

RUN /opt/keycloak/bin/kc.sh build \
  --health-enabled=false \
  --metrics-enabled=false \
  --cache=ispn \
  --cache-stack=tcp
RUN /opt/keycloak/bin/kc.sh show-config

FROM quay.io/keycloak/keycloak:20.0.3
COPY --from=builder /opt/keycloak/ /opt/keycloak/
WORKDIR /opt/keycloak

COPY keycloak.sh /keycloak.sh

ENTRYPOINT ["/keycloak.sh"]
