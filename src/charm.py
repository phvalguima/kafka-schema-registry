#!/usr/bin/env python3
# Copyright 2021 pguimaraes
# See LICENSE file for licensing details.

import base64
import logging
import socket
import yaml

from ops.main import main
from ops.model import (
    BlockedStatus,
    ActiveStatus,
    MaintenanceStatus
)

from charmhelpers.core.templating import render
from charmhelpers.core.host import (
    service_resume,
    service_running,
    service_restart,
    service_reload
)

from wand.apps.relations.tls_certificates import (
    TLSCertificateRequiresRelation,
    TLSCertificateDataNotFoundInRelationError,
    TLSCertificateRelationNotPresentError
)
from wand.apps.kafka import KafkaJavaCharmBase
from wand.apps.relations.kafka_mds import (
    KafkaMDSRelation,
    KafkaMDSRequiresRelation
)
from wand.apps.relations.kafka_relation_base import (
    KafkaRelationBaseNotUsedError,
    KafkaRelationBaseTLSNotSetError
)
from wand.apps.relations.kafka_listener import (
    KafkaListenerRelation,
    KafkaListenerRequiresRelation,
    KafkaListenerRelationNotSetError
)
from wand.security.ssl import PKCS12CreateKeystore
from wand.security.ssl import genRandomPassword
from wand.security.ssl import generateSelfSigned

logger = logging.getLogger(__name__)


class KafkaSchemaRegistryCharm(CharmBase):

    CONFLUENT_PACKAGES = [
        "confluent-common",
        "confluent-rest-utils",
        "confluent-metadata-service",
        "confluent-ce-kafka-http-server",
        "confluent-kafka-rest",
        "confluent-server-rest",
        "confluent-telemetry",
        "confluent-server",
        "confluent-schema-registry",
        "confluent-security"
    ]

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed,
                               self._on_config_changed)
        self.framework.observe(self.on.listener_relation_joined,
                               self.on_listener_relation_joined)
        self.framework.observe(self.on.listener_relation_changed,
                               self.on_listener_relation_changed)
        self.framework.observe(self.on.schemaregistry_relation_joined,
                               self.on_schemaregistry_relation_joined)
        self.framework.observe(self.on.schemaregistry_relation_changed,
                               self.on_schemaregistry_relation_changed)
        self.framework.observe(self.on.mds_relation_joined,
                               self.on_mds_relation_joined)
        self.framework.observe(self.on.mds_relation_changed,
                               self.on_mds_relation_changed)
        self.framework.observe(self.on.update_status,
                               self._on_update_status)
        # Relation managers
        self.listener = KafkaListenerRequiresRelation(
            self, 'listeners')
        self.sr = KafkaSchemaRegistryProvidesRelation(self, "schemaregistry")
        self.certificates = \
            TLSCertificateRequiresRelation(self, 'certificates')
        self.mds = MDSRequiresRelation(self, "mds")

    def on_listener_relation_joined(self, event):
        # If no certificate available, defer this event and wait
        if not self._cert_relation_set(event, self.listener):
            return
        req = {}
        if self.is_sasl_enabled():
            # TODO: implement it
            req["SASL"] = {}
        req["is_public"] = False
        if self.is_ssl_enabled():
            req["cert"] = self.get_ssl_cert()
        self.listener.set_request(req)
        self._on_config_changed(event)

    def on_listener_relation_changed(self, event):
        self.on_listener_relation_joined(event)

    def on_certificates_relation_joined(self, event):
        self.certificates.on_tls_certificate_relation_joined(event)
        self._on_config_changed(event)

    def on_certificates_relation_changed(self, event):
        self.certificates.on_tls_certificate_relation_changed(event)
        self._on_config_changed(event)

    def on_mds_relation_joined(self, event):
        # If no certificate available, defer this event and wait
        if not self._cert_relation_set(event, self.mds):
            return
        self._on_config_changed(event)

    def on_mds_relation_changed(self, event):
        self.on_mds_relation_joined(event)

    def _on_update_status(self, event):
        if not service_running(self.service):
            self.model.unit.status = \
                BlockedStatus("{} not running".format(self.service))
            return
        self.model.unit.status = \
            ActiveStatus("{} is running".format(self.service))

    def is_sasl_enabled(self):
        # TODO: implement sasl
        return False

    def is_rbac_enabled(self):
        if self.distro == "apache":
            return False
        return False

    def is_ssl_enabled(self):
        return len(self.get_ssl_cert()) > 0 and len(self.get_ssl_key()) > 0

    def _on_install(self, event):
        super()._on_install(event)
        self.model.unit.status = MaintenanceStatus("Starting installation")
        logger.info("Starting installation")
        packages = []
        # TODO(pguimares): implement install_tarball logic
        # self._install_tarball()
        if self.distro == "confluent":
            packages = self.CONFLUENT_PACKAGES
        else:
            raise Exception("Not Implemented Yet")
        super().install_packages('openjdk-11-headless', packages)

    def _check_if_ready_to_start(self):
        if not self.cluster.is_ready:
            self.model.unit.status = \
                BlockedStatus("Waiting for other cluster units")
            return False
        self.model.unit.status = \
            ActiveStatus("{} running".format(self.service))
        return True

    def get_ssl_cert(self):
        if self.config["generate-root-ca"]:
            return self.ks.ssl_cert
        if len(self.config.get("ssl_cert")) > 0 and \
           len(self.config.get("ssl_key")) > 0:
            return base64.b64decode(self.config["ssl_cert"]).decode("ascii")
        certs = self.certificates.get_server_certs()
        c = certs[self.sr.binding_addr]["cert"] + \
            self.certificates.get_chain()
        logger.debug("SSL Certificate chain"
                     " from tls-certificates: {}".format(c))
        return c

    def get_ssl_key(self):
        if self.config["generate-root-ca"]:
            return self.ks.ssl_key
        if len(self.config.get("ssl_cert")) > 0 and \
           len(self.config.get("ssl_key")) > 0:
            return base64.b64decode(self.config["ssl_key"]).decode("ascii")
        certs = self.certificates.get_server_certs()
        k = certs[self.sr.binding_addr]["key"]
        return k

    def get_ssl_keystore(self):
        path = self.config.get("keystore-path", "")
        return path

    def get_ssl_truststore(self):
        path = self.config.get("truststore-path", "")
        return path

    def get_ssl_listener_cert(self):
        if self.config["generate-root-ca"]:
            return self.ks.ssl_cert
        if len(self.config.get("ssl_listener_cert")) > 0 and \
           len(self.config.get("ssl_listener_key")) > 0:
            return base64.b64decode(self.config["ssl_listener_cert"]).decode("ascii")
        certs = self.certificates.get_server_certs()
        c = certs[self.listener.binding_addr]["cert"] + \
            self.certificates.get_chain()
        logger.debug("SSL Certificate chain"
                     " from tls-certificates: {}".format(c))
        return c

    def get_ssl_listener_key(self):
        if self.config["generate-root-ca"]:
            return self.ks.ssl_key
        if len(self.config.get("ssl_listener_cert")) > 0 and \
           len(self.config.get("ssl_listener_key")) > 0:
            return base64.b64decode(self.config["ssl_listener_key"]).decode("ascii")
        certs = self.certificates.get_server_certs()
        k = certs[self.listener.binding_addr]["key"]
        return k

    def get_ssl_keystore(self):
        path = self.config.get("keystore-listener-path", "")
        return path

    def get_ssl_truststore(self):
        path = self.config.get("truststore-listener-path", "")
        return path


    def _generate_keystores(self):
        if self.config["generate-root-ca"] and \
            (len(self.ks.quorum_cert) > 0 and
             len(self.ks.quorum_key) > 0 and
             len(self.ks.ssl_cert) > 0 and
             len(self.ks.ssl_key) > 0):
            logger.info("Certificate already auto-generated and set")
            return
        if self.config["generate-root-ca"]:
            logger.info("Certificate needs to be auto generated")
            self.ks.ssl_cert, self.ks.ssl_key = \
                generateSelfSigned(self.unit_folder,
                                   certname="ssl-zookeeper-root-ca",
                                   user=self.config["user"],
                                   group=self.config["group"],
                                   mode=0o600)
            logger.info("Certificates and keys generated")
        else:
            # Check if the certificates remain the same
            if self.ks.ssl_cert == self.get_ssl_cert() and \
                    self.ks.quorum_key == self.get_quorum_key():
                # Yes, they do, leave this method as there is nothing to do.
                logger.info("Certificates and keys remain the same")
                return
            # Certs already set either as configs or certificates relation
            self.ks.ssl_cert = self.get_ssl_cert()
            self.ks.ssl_key = self.get_ssl_key()
        if len(self.ks.ssl_cert) > 0 and \
           len(self.ks.ssl_key) > 0:
            logger.info("Create PKCS12 cert/key for zookeeper relation")
            self.ks.ks_password = genRandomPassword()
            filename = genRandomPassword(6)
            PKCS12CreateKeystore(
                self.get_ssl_keystore(),
                self.ks.ks_password,
                self.get_ssl_cert(),
                self.get_ssl_key(),
                user=self.config["user"],
                group=self.config["group"],
                mode=0o640,
                openssl_chain_path="/tmp/" + filename + ".chain",
                openssl_key_path="/tmp/" + filename + ".key",
                openssl_p12_path="/tmp/" + filename + ".p12",
                ks_regenerate=self.config.get(
                                  "regenerate-keystore-truststore", False))

    def _get_service_name(self):
        if self.distro == 'confluent':
            self.service = 'confluent-schema-registry'
        elif self.distro == "apache":
            self.service = "schema-registry"
        return self.service

    def _render_schema_registry_properties(self):
        logger.info("Start to render schema-registry properties")
        sr_props = \
            yaml.safe_load(self.config.get(
                "schema-registry-properties", "")) or {}
        auth_method = self.config.get(
            "rest_authentication_method", "").lower()
        if auth_method == "none":
            sr_props["authentication.method"] = "None"
            sr_props["authentication.roles"] = "**"
        elif auth_method == "basic":
            sr_props["authentication.method"] = "BASIC"
            sr_props["authentication.roles"] = \
                self.config.get("rest_authentication", "")
            sr_props["authentication.realm"] = "SchemaRegistry-Props"
        else:
            logger.info("Authentication method {}"
                        " not implemented yet".format(auth_method))
            raise SchemaRegistryCharmNotValidOptionSetError(
                self.config.get("rest_authentication_method"))
        if self.mds.relations:
            sr_props["confluent.metadata.bootstrap.server.urls"] = \
                self.mds.get_server_list()
            if self.mds.is_auth_set():
                sr_props["confluent.metadata.basic.auth.user.info"] = \
                    "{}:{}".format(
                        self.mds.get_mds_user(),
                        self.mds.get_mds_password())
                if self.mds.is_auth_set():
                    sr_props["confluent.metadata.http.auth.credentials"
                             ".provider"] = self.mds.get_cred_provider()
                    sr_props["confluent.schema.registry.auth"
                             ".mechanism"] = self.mds.get_auth_mech()
                    sr_props["confluent.schema.registry.authorizer"
                             ".class"] = self.mds.get_authorizer()
        else:
            self.model.unit.status = \
                BlockedStatus("Missing MDS relation")
            event.defer()
            raise SchemaRegistryCharmMissingRelationError("mds"))

        sr_props["debug"] = self.config.get("debug", False)
        sr_props["host.name"] = get_hostname(self.sr.advertise_addr)
        sr_props["inter.instance.protocol"] = self.config.get("protocol", "https").lower()
        sr_props["listeners"] = "{}://{}:{}".format(
            self.config.get("protocol", "https").lower(),
            get_hostname(self.sr.advertise_addr),
            self.config.get("port", 8081))
        sr_props["schema.registry.group.id"] = self.config.get("group-id", "schema-registry")
        if self.config.get("client-auth", False):
            sr_props["ssl.client.auth"] = "true"
        if self.is_rbac_enabled():
            sr_props["schema.registry.resource.extension.class"] = \
                self.config.get("resource-extension-class", "")
            sr_props["rest.servlet.initializor.classes"] = \
                "io.confluent.common.security.jetty.initializer"
                ".InstallBearerOrBasicSecurityHandler"
            # TODO: Implement RBAC: public.key.path=/var/ssl/private/public.pem
        if self.get_ssl_cert() and self.get_ssl_key():
            sr_props["security.protocol"] = "SSL"
            sr_props["ssl.key.password"] = self.ks.ks_password
            sr_props["ssl.keystore.location"] = self.get_ssl_keystore()
            sr_props["ssl.keystore.password"] = self.ks.ks_password
            # Leave truststore unset if willing to use java's default truststore instead
            if self.get_ssl_truststore() and len(self.get_ssl_truststore()) > 0:
                sr_props["ssl.truststore.location"] = self.get_ssl_truststore()
                sr_props["ssl.truststore.password"] = self.ks.ts_password
                self.sr.set_TLS_auth(
                    self.get_ssl_cert(),
                    self.get_ssl_truststore(),
                    self.ks.ts_password,
                    user=self.config["user"],
                    group=self.config["group"],
                    mode=0o640)

        sr_props["kafkastore.bootstrap.servers"] = self.listener.get_bootstrap_servers()
        sr_props["kafkastore.topic"] = "_schemas"
        sr_props["kafkastore.topic.replication.factor"] = 3
        if self.get_listener_cert() and \
           self.get_listener_key():
            sr_props["kafkastore.security.protocol"] = "SSL"
            # unset listener-keystore if mutual TLS is disabled
            if len(self.get_listener_keystore()) > 0:
                sr_props["kafkastore.ssl.key.password"] = self.ks.ks_listener_pwd
                sr_props["kafkastore.ssl.keystore.location"] = self.get_listener_keystore()
                sr_props["kafkastore.ssl.keystore.password"] = self.ks.ks_listener_pwd
            # unset if willing to use java default truststore instead
            if len(self.get_listener_truststore()) > 0:
                sr_props["kafkastore.ssl.truststore.location"] = self.get_listener_truststore()
                sr_props["kafkastore.ssl.truststore.password"] = self.ks.ts_listener_pwd
                self.listener.set_TLS_auth(
                    self.get_listner_cert(),
                    self.get_listener_truststore(),
                    self.ks.ts_listener_pwd,
                    user=self.config["user"],
                    group=self.config["group"],
                    mode=0o640)

# kafkastore.sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required username="schema_registry" password="password123" metadataServerUrls="https://ansiblebroker3.example.com:$
# kafkastore.sasl.login.callback.handler.class=io.confluent.kafka.clients.plugins.auth.token.TokenUserLoginCallbackHandler
# kafkastore.sasl.mechanism=OAUTHBEARER

        logger.debug("Options are: {}".format(",".join(sr_props)))
        render(source="schema-registry.properties.j2",
               target="/etc/schema-registry/schema-registry.properties",
               owner=self.config.get('user'),
               group=self.config.get("group"),
               perms=0o640,
               context={
                   "sr_props": sr_props
               })

    def _render_sr_log4j_properties(self):
        root_logger = self.config.get("log4j-root-logger", None) or \
            "INFO, stdout, file"
        self.model.unit.status = MaintenanceStatus("Rendering log4j...")
        logger.debug("Rendering log4j")
        render(source="schema-registry_log4j.properties.j2",
               target="/etc/schema-registry/log4j.properties",
               owner=self.config.get('user'),
               group=self.config.get("group"),
               perms=0o640,
               context={
                   "root_logger": root_logger
               })

    def _on_config_changed(self, event):
        if not self._cert_relation_set(event):
            return
        self.model.unit.status = \
            MaintenanceStatus("generate certs and keys if needed")
        logger.debug("Running _generate_keystores()")
        self._generate_keystores()
        self.model.unit.status = \
            MaintenanceStatus("Render schema-registry.properties")
        logger.debug("Running render_schema_registry_properties()")
        self._render_schema_registry_properties()
        self.model.unit.status = MaintenanceStatus("Render log4j properties")
        logger.debug("Running log4j properties renderer")
        self._render_log4j_properties()
        self.model.unit.status = \
            MaintenanceStatus("Render service override conf file")
        logger.debug("Render override.conf")
        self.render_service_override_file(
            target="/etc/systemd/system/"
                   "{}.service.d/override.conf".format(self.service))
        if self._check_if_ready_to_start():
            logger.info("Service ready or start, restarting it...")
            # Unmask and enable service
            service_resume(self.service)
            # Reload and restart
            service_reload(self.service)
            service_restart(self.service)
            logger.debug("finished restarting")
        if not service_running(self.service):
            logger.warning("Service not running that "
                           "should be: {}".format(self.service))
            BlockedStatus("Service not running {}".format(self.service))


if __name__ == "__main__":
    main(KafkaSchemaRegistryCharm)
