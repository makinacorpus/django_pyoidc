#!/usr/bin/env bash
set -eu

#echo " * Env for KC_*"
#env| grep KC_
#echo " * Env for KEYCLOAK*"
#env| grep KEYCLOAK

#KC_DB_URL="jdbc:postgresql://${KC_DB_URL_HOST}:${KC_DB_URL_PORT}/${KC_DB_URL_DATABASE}"
#export KC_DB_URL=${KC_DB_URL}

OPT=""

OPT="${OPT} --spi-theme-static-max-age=-1 \
  --spi-theme-cache-themes=false \
  --spi-theme-cache-templates=false"

OPT="--optimized --http-port=${KC_HTTP_PORT-8080} \
    --spi-theme-welcome-theme=${KC_WELCOME_THEME-keycloak}"

## enables detection of proxy real Host for X-Fowarded-Headers
## while allowing proxy->keycloak HTTP communication (non-TTLS)
OPT="${OPT} \
      --hostname-strict=false \
      --hostname-strict-https=false \
      --http-enabled=true \
      --proxy=edge"

## success messages. default debug
## debug, error, fatal, info, trace, warn
## Propagate success events to INFO instead of DEBUG, to expose successful
## logins for log analysis
OPT="${OPT}  \
  --spi-events-listener-jboss-logging-success-level=info"

OPT="${OPT} \
  --log-level=${ROOT_LOGLEVEL-INFO}"

if [ "x${VERBOSE_KC_COMMAND-0}" == "x1" ]; then
    PREFIX=" --verbose"
else
    PREFIX=""
fi

if [ "x${KEYCLOAK_IMPORT_ONLY-0}" == "x1" ]; then
    OPT="\
      --dir /config \
      --override true \
    "
  echo " * Starting keycloak in IMPORT mode"
  echo " * Using /opt/keycloak/bin/kc.sh import with theses options:"
  echo " ${PREFIX} import ${OPT}"
  exec /opt/keycloak/bin/kc.sh ${PREFIX} import ${OPT}

else

  echo " * Starting keycloak"
  echo " * Using /opt/keycloak/bin/kc.sh start with theses options:"
  echo " ${PREFIX} start ${OPT}"
  exec /opt/keycloak/bin/kc.sh ${PREFIX} start ${OPT}

fi
exit "$?"