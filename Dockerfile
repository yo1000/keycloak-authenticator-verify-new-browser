FROM jboss/keycloak:12.0.1

RUN mkdir -p /opt/jboss/keycloak/providers
ADD target/keycloak-authenticator-verify-new-browser.jar /opt/jboss/keycloak/providers/keycloak-authenticator-verify-new-browser.jar

RUN mkdir -p /opt/jboss/keycloak/themes/base/login/messages
ADD themes/base/login/verify-new-browser-challenge.ftl /opt/jboss/keycloak/themes/base/login/verify-new-browser-challenge.ftl
ADD themes/base/login/verify-new-browser-complete.ftl  /opt/jboss/keycloak/themes/base/login/verify-new-browser-complete.ftl
ADD themes/base/login/messages/messages_en.properties /opt/jboss/keycloak/themes/base/login/messages/messages_en.properties
ADD themes/base/login/messages/messages_ja.properties /opt/jboss/keycloak/themes/base/login/messages/messages_ja.properties

RUN mkdir -p /opt/jboss/keycloak/themes/base/email/text
RUN mkdir -p /opt/jboss/keycloak/themes/base/email/html
RUN mkdir -p /opt/jboss/keycloak/themes/base/email/messages
ADD themes/base/email/text/verify-new-browser.ftl /opt/jboss/keycloak/themes/base/email/text/verify-new-browser.ftl
ADD themes/base/email/html/verify-new-browser.ftl /opt/jboss/keycloak/themes/base/email/html/verify-new-browser.ftl
ADD themes/base/email/messages/messages_en.properties /opt/jboss/keycloak/themes/base/email/messages/messages_en.properties
ADD themes/base/email/messages/messages_ja.properties /opt/jboss/keycloak/themes/base/email/messages/messages_ja.properties

RUN ls /opt/jboss/keycloak/themes/
RUN ls /opt/jboss/keycloak/themes/base/
RUN ls /opt/jboss/keycloak/themes/base/email/
RUN ls /opt/jboss/keycloak/themes/base/email/text/
RUN ls /opt/jboss/keycloak/themes/base/email/html/

RUN pwd
RUN ls
RUN ls /opt
RUN ls /opt/jboss
RUN ls /opt/jboss/keycloak
