#!/usr/bin/env python3
# Copyright 2021 pguimaraes
# See LICENSE file for licensing details.

import base64
import logging
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
    TLSCertificateRequiresRelation
)
from wand.apps.kafka import KafkaJavaCharmBase
from wand.apps.relations.kafka_mds import (
    KafkaMDSRequiresRelation
)
from wand.apps.relations.kafka_relation_base import (
    KafkaRelationBaseNotUsedError,
    KafkaRelationBaseTLSNotSetError
)
from wand.apps.relations.kafka_listener import (
    KafkaListenerRequiresRelation,
    KafkaListenerRelationNotSetError
)
from wand.apps.relations.kafka_schema_registry import (
    KafkaSchemaRegistryProvidesRelation
)
from wand.security.ssl import PKCS12CreateKeystore
from wand.security.ssl import genRandomPassword
from wand.security.ssl import generateSelfSigned
from wand.contrib.linux import get_hostname

logger = logging.getLogger(__name__)


class SchemaRegistryCharmNotValidOptionSetError(Exception):

    def __init__(self, option):
        super().__init__("Option {} has no valid content".format(option))


class SchemaRegistryCharmMissingRelationError(Exception):

    def __init__(self, relation_name):
        super().__init__("Missing relation to: {}".format(relation_name))


class SchemaRegistryCharmUnsupportedParamError(Exception):

    def __init__(self, message):
        super().__init__(message)

class KafkaSchemaRegistryCharm(KafkaJavaCharmBase):

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
        self.framework.observe(self.on.listeners_relation_joined,
                               self.on_listeners_relation_joined)
        self.framework.observe(self.on.listeners_relation_changed,
                               self.on_listeners_relation_changed)
        self.framework.observe(self.on.schemaregistry_relation_joined,
                               self.on_schemaregistry_relation_joined)
        self.framework.observe(self.on.schemaregistry_relation_changed,
                               self.on_schemaregistry_relation_changed)
        self.framework.observe(self.on.mds_relation_joined,
                               self.on_mds_relation_joined)
        self.framework.observe(self.on.mds_relation_changed,
                               self.on_mds_relation_changed)
        self.framework.observe(self.on.certificates_relation_joined,
                               self.on_certificates_relation_joined)
        self.framework.observe(self.on.certificates_relation_changed,
                               self.on_certificates_relation_changed)
        self.framework.observe(self.on.update_status,
                               self._on_update_status)
        # Relation managers
        self.listener = KafkaListenerRequiresRelation(
            self, 'listeners')
        self.sr = KafkaSchemaRegistryProvidesRelation(self, "schemaregistry")
        self.certificates = \
            TLSCertificateRequiresRelation(self, 'certificates')
        self.mds = KafkaMDSRequiresRelation(self, "mds")
        # States for the SSL part
        self.get_ssl_methods_list = [
            self.get_ssl_cert, self.get_ssl_key,
            self.get_ssl_listener_cert, self.get_ssl_listener_key]
        self.ks.set_default(ssl_cert="")
        self.ks.set_default(ssl_key="")
        self.ks.set_default(ssl_listener_cert="")
        self.ks.set_default(ssl_listener_key="")
        self.ks.set_default(ks_listener_pwd=genRandomPassword())
        self.ks.set_default(ts_listener_pwd=genRandomPassword())
        self.ks.set_default(listener_plaintext_pwd=genRandomPassword(24))

    def on_schemaregistry_relation_joined(self, event):
        if not self._cert_relation_set(
                event, self.sr,
                extra_sans=self.config.get("schema_url", None)):
            return
        self._on_config_changed(event)

    def on_schemaregistry_relation_changed(self, event):
        if not self._cert_relation_set(
                event, self.sr,
                extra_sans=self.config.get("schema_url", None)):
            return
        self._on_config_changed(event)

    def _generate_listener_request(self):
        req = {}
        if self.is_sasl_enabled():
            # TODO: implement it
            req["SASL"] = {}
        req["is_public"] = False
        if self.is_ssl_enabled():
            req["cert"] = self.get_ssl_cert()
        if len(self.ks.listener_plaintext_pwd) == 0:
            self.ks.listener_plaintext_pwd = genRandomPassword(24)
        req["plaintext_pwd"] = self.ks.listener_plaintext_pwd
        self.listener.set_request(req)

    def on_listeners_relation_joined(self, event):
        # If no certificate available, defer this event and wait
        if not self._cert_relation_set(event, self.listener):
            return
        self._on_config_changed(event)

    def on_listeners_relation_changed(self, event):
        self.on_listeners_relation_joined(event)

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
        make_dirs = ["/var/log/schema-registry"]
        self.set_folders_and_permissions(make_dirs)

    def _check_if_ready_to_start(self):
        self.model.unit.status = \
            ActiveStatus("{} running".format(self.service))
        return True

    # STORE GET METHODS
    def get_ssl_keystore(self):
        path = self.config.get("keystore-path", "")
        return path

    def get_ssl_truststore(self):
        path = self.config.get("truststore-path", "")
        return path

    def get_ssl_listener_keystore(self):
        path = self.config.get("listener-keystore-path", "")
        return path

    def get_ssl_listener_truststore(self):
        path = self.config.get("listener-truststore-path", "")
        return path

    # SSL GET METHODS
    def get_ssl_listener_cert(self):
        return self._get_ssl(self.listener, "cert")

    def get_ssl_listener_key(self):
        return self._get_ssl(self.listener, "key")

    def get_ssl_cert(self):
        return self._get_ssl(self.sr, "cert")

    def get_ssl_key(self):
        return self._get_ssl(self.sr, "key")

    def _get_ssl(self, relation, ty):
        prefix = None
        rel = None
        if isinstance(relation, KafkaListenerRequiresRelation):
            prefix = "ssl_listener"
        elif isinstance(relation, KafkaSchemaRegistryProvidesRelation):
            prefix = "ssl"
        if len(self.config.get(prefix + "_cert")) > 0 and \
           len(self.config.get(prefix + "_key")) > 0:
                if ty == "cert":
                    return base64.b64decode(
                        self.config[prefix + "_cert"]).decode("ascii")
                else:
                    return base64.b64decode(
                        self.config[prefix + "_key"]).decode("ascii")

        certs = self.certificates.get_server_certs()
        c = certs[relation.binding_addr][ty]
        if ty == "cert":
            c = c + \
                self.certificates.get_chain()
        logger.debug("SSL {} for {}"
                     " from tls-certificates: {}".format(ty, prefix, c))
        return c

    def _generate_keystores(self):
        ks = [[self.ks.ssl_cert, self.ks.ssl_key, self.ks.ks_password,
               self.get_ssl_cert, self.get_ssl_key, self.get_ssl_keystore],
              [self.ks.ssl_listener_cert, self.ks.ssl_listener_key,
               self.ks.ks_listener_pwd,
               self.get_ssl_listener_cert, self.get_ssl_listener_key,
               self.get_ssl_listener_keystore]]
        # INDICES WITHIN THE LIST:
        CERT, KEY, PWD, GET_CERT, GET_KEY, GET_KEYSTORE = 0,1,2,3,4,5
        # Generate the keystores if cert/key exists
        for t in ks:
            if t[CERT] == t[GET_CERT]() and \
               t[KEY] == t[KEY]():
                # Certs and keys are the same
                logger.info("Same certs and keys for {}".format(t[CERT]))
                continue
            t[CERT] = t[GET_CERT]()
            t[KEY] = t[GET_KEY]()
            if len(t[CERT]) > 0 and len(t[KEY]) > 0 and t[GET_KEYSTORE]():
                logger.info("Create PKCS12 cert/key for {}".format(t[CERT]))
                logger.debug("Iteration: {}".format(t))
                filename = genRandomPassword(6)
                PKCS12CreateKeystore(
                    t[GET_KEYSTORE](),
                    t[PWD],
                    t[GET_CERT](),
                    t[GET_KEY](),
                    user=self.config["user"],
                    group=self.config["group"],
                    mode=0o640,
                    openssl_chain_path="/tmp/" + filename + ".chain",
                    openssl_key_path="/tmp/" + filename + ".key",
                    openssl_p12_path="/tmp/" + filename + ".p12",
                    ks_regenerate=self.config.get(
                        "regenerate-keystore-truststore", False))
            elif not t[GET_KEYSTORE]():
                logger.debug("Keystore not found on Iteration: {}".format(t))

    def _get_service_name(self):
        if self.distro == 'confluent':
            self.service = 'confluent-schema-registry'
        elif self.distro == "apache":
            self.service = "schema-registry"
        return self.service

    def _render_schemaregistry_properties(self, event):
        logger.info("Start to render schema-registry properties")
        sr_props = \
            yaml.safe_load(self.config.get(
                "schema-registry-properties", "")) or {}
        if self.config.get("confluent_license_topic") and \
           len(self.config.get("confluent_license_topic")) > 0:
            sr_props["confluent.license.topic"] = self.config.get("confluent_license_topic")

        auth_method = self.config.get(
            "rest_authentication_method", "").lower()
        # Manage authentication
        if auth_method == "none":
            sr_props["authentication.method"] = "NONE"
            sr_props["authentication.roles"] = "**"
        elif auth_method == "basic":
            sr_props["authentication.method"] = "BASIC"
            sr_props["authentication.roles"] = \
                self.config.get("rest_authentication", "")
            # TODO: Create this field on the jaas.conf file
            sr_props["authentication.realm"] = "SchemaRegistry-Props"
        elif auth_method == "bearer":
            # TODO: Set it correctly
            pass
        else:
            logger.info("Authentication method {}"
                        " not implemented yet".format(auth_method))
            raise SchemaRegistryCharmNotValidOptionSetError(
                self.config.get("rest_authentication_method"))

        # MDS Relation
        if not self.mds.relation:
            # MDS is only available for Confluent
            logger.warning("MDS relation not detected")
        elif self.mds.relation and self.distro != "confluent":
            raise SchemaRegistryCharmUnsupportedParamError(
                "kafka distro {} does not support MDS relation".format(self.distro)
            )
        else:
            # MDS relation present
            mds_opts = self.mds.get_options()
            dist_props = {**dist_props, **mds_props}

        sr_props["debug"] = self.config.get("debug", False)
        sr_props["host.name"] = get_hostname(self.sr.advertise_addr)

        # Listeners relation
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
                "io.confluent.common.security.jetty.initializer" \
                + ".InstallBearerOrBasicSecurityHandler"
            # TODO: Implement RBAC: public.key.path=/var/ssl/private/public.pem
        # Check if schema_url starts with https. If yes, then set up ssl
        if self.config.get("schema_url", "").startswith("https://") and \
           self.is_ssl_enabled():
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
        if self.get_ssl_listener_cert() and \
           self.get_ssl_listener_key():
            sr_props["kafkastore.security.protocol"] = "SSL"
            # unset listener-keystore if mutual TLS is disabled
            if len(self.get_ssl_listener_keystore()) > 0:
                sr_props["kafkastore.ssl.key.password"] = self.ks.ks_listener_pwd
                sr_props["kafkastore.ssl.keystore.location"] = self.get_ssl_listener_keystore()
                sr_props["kafkastore.ssl.keystore.password"] = self.ks.ks_listener_pwd
            # unset if willing to use java default truststore instead
            if len(self.get_ssl_listener_truststore()) > 0:
                sr_props["kafkastore.ssl.truststore.location"] = self.get_ssl_listener_truststore()
                sr_props["kafkastore.ssl.truststore.password"] = self.ks.ts_listener_pwd
                self.listener.set_TLS_auth(
                    self.get_ssl_listener_cert(),
                    self.get_ssl_listener_truststore(),
                    self.ks.ts_listener_pwd,
                    user=self.config["user"],
                    group=self.config["group"],
                    mode=0o640)
        else: # No SSL defined
            sr_props["kafkastore.security.protocol"] = "PLAINTEXT"

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
            MaintenanceStatus("Generate Listener settings")
        self._generate_listener_request()

        self.model.unit.status = \
            MaintenanceStatus("Setting schema registry parameters")
        # Manage Schema Registry relation
        self.sr.set_schema_url(self.config.get("schema_url", ""))
        self.sr.set_converter(self.config.get("schema_converter", ""))
        self.sr.set_enhanced_avro_support(
            self.config.get("enhanced_avro_schema_support", ""))
        self.model.unit.status = \
            MaintenanceStatus("Render schema-registry.properties")
        logger.debug("Running render_schemaregistry_properties()")
        try:
            self._render_schemaregistry_properties(event)
        except SchemaRegistryCharmNotValidOptionSetError:
            # Returning as we need to wait for a config change and that
            # will trigger a new event
            return
        except SchemaRegistryCharmMissingRelationError:
            # same reason as above, waiting for an add-relation
            return
        self.model.unit.status = MaintenanceStatus("Render log4j properties")
        logger.debug("Running log4j properties renderer")
        self._render_sr_log4j_properties()
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
