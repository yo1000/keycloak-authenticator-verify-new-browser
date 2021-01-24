FROM jboss/keycloak:12.0.1

RUN mkdir -p /opt/jboss/keycloak/providers
ADD target/keycloak-authenticator-new-browser-check.jar /opt/jboss/keycloak/providers/keycloak-authenticator-new-browser-check.jar

RUN mkdir -p /opt/jboss/keycloak/themes/base/login
ADD themes/base/login/new-browser-check.ftl /opt/jboss/keycloak/themes/base/login/new-browser-check.ftl

RUN pwd
RUN ls

RUN ls /opt

RUN ls /opt/jboss

RUN ls /opt/jboss/keycloak
