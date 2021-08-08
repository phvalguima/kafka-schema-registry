#!/usr/bin/env python3
# Copyright 2021 pguimaraes
# See LICENSE file for licensing details.

import json
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

from charmhelpers.core.hookenv import (
    open_port,
    close_port
)

from wand.apps.relations.tls_certificates import (
    TLSCertificateRequiresRelation,
    TLSCertificateDataNotFoundInRelationError,
    TLSCertificateRelationNotPresentError
)
from wand.apps.kafka import (
    KafkaJavaCharmBase,
    KafkaCharmBaseFeatureNotImplementedError,
    KafkaJavaCharmBasePrometheusMonitorNode,
    KafkaJavaCharmBaseNRPEMonitoring
)
from wand.apps.relations.kafka_mds import (
    KafkaMDSRequiresRelation
)
from wand.apps.relations.kafka_relation_base import (
    KafkaRelationBaseTLSNotSetError
)
from wand.apps.relations.kafka_listener import (
    KafkaListenerRequiresRelation,
    KafkaListenerRelationNotSetError
)
from wand.apps.relations.kafka_schema_registry import (
    KafkaSchemaRegistryProvidesRelation
)
from wand.security.ssl import genRandomPassword, CreateTruststore
from wand.contrib.linux import get_hostname
from wand.apps.relations.kafka_confluent_center import (
    KafkaC3RequiresRelation
)

from loadbalancer_interface import LBProvider


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
        self.framework.observe(self.on.cluster_relation_joined,
                               self._on_cluster_relation_joined)
        self.framework.observe(self.on.cluster_relation_changed,
                               self._on_cluster_relation_changed)
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
        self.framework.observe(self.on.c3_relation_joined,
                               self.on_c3_relation_joined)
        self.framework.observe(self.on.c3_relation_changed,
                               self.on_c3_relation_changed)
        self.framework.observe(self.on.update_status,
                               self._on_update_status)
        # Load balancer settings
        self.lb_provider = LBProvider(self, "lb-provider")
        self.framework.observe(self.lb_provider.on.available,
                               self._on_lb_provider_available)
        # Load balancer configs:
        self.ks.set_default(lb_port=0)
        self.ks.set_default(lb_api_ip="")
        self.ks.set_default(api_is_public=False)
        #########
        self.ks.set_default(ports=[0])
        # Relation managers
        self.listener = KafkaListenerRequiresRelation(
            self, 'listeners')
        self.sr = KafkaSchemaRegistryProvidesRelation(self, "schemaregistry")
        self.certificates = \
            TLSCertificateRequiresRelation(self, 'certificates')
        self.mds = KafkaMDSRequiresRelation(self, "mds")
        self.c3 = KafkaC3RequiresRelation(self, "c3")
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
        # LMA integrations
        self.prometheus = \
            KafkaJavaCharmBasePrometheusMonitorNode(
                self, 'prometheus-manual',
                port=self.config.get("jmx-exporter-port", 9404),
                internal_endpoint=self.config.get(
                    "jmx_exporter_use_internal", False),
                labels=self.config.get("jmx_exporter_labels", None))
        self.nrpe = KafkaJavaCharmBaseNRPEMonitoring(
            self,
            svcs=[self._get_service_name()],
            endpoints=[],
            nrpe_relation_name='nrpe-external-master')

    def _on_lb_provider_available(self, event):
        if not (self.unit.is_leader() and self.lb_provider.is_available):
            return
        # Check if there is any configuration changes:
        if self.ks.lb_port == self.config["clientPort"] and \
           self.ks.lb_api_ip == self.config["api_ip"] and \
           self.ks.api_is_public == self.config["api_is_public"]:
            # configs are the same, just return
            return
        request = self.lb_provider.get_request("lb-consumer")
        request.protocol = request.protocols.tcp
        request.port_mapping = {
            self.config["clientPort"]: self.config["clientPort"]
        }
        if len(self.config.get("api_ip", "")) > 0:
            request.ingress_address = self.config["api_ip"]
        request.public = self.config["api_is_public"]
        self.lb_provider.send_request(request)
        # Now, save the data for the next request
        self.ks.lb_port = self.config["clientPort"]
        self.ks.lb_api_ip = self.config["api_ip"]
        self.ks.api_is_public = self.config["api_is_public"]

    def is_jmxexporter_enabled(self):
        if self.prometheus.relations:
            return True
        return False

    @property
    def ctx(self):
        return json.loads(self.ks.config_state)

    @ctx.setter
    def ctx(self, c):
        self.ks.ctx = json.dumps(c)

    def _on_cluster_relation_joined(self, event):
        self._on_config_changed(event)

    def _on_cluster_relation_changed(self, event):
        self._on_config_changed(event)
        if not self.prometheus.relations:
            return
        if len(self.prometheus.relations) > 0:
            self.prometheus.on_prometheus_relation_changed(event)

    def on_c3_relation_joined(self, event):
        self._on_config_changed(event)

    def on_c3_relation_changed(self, event):
        self._on_config_changed(event)

    def on_schemaregistry_relation_joined(self, event):
        self.sr.on_schema_registry_relation_joined(event)
        self._on_config_changed(event)

    def on_schemaregistry_relation_changed(self, event):
        self.sr.on_schema_registry_relation_changed(event)
        self._on_config_changed(event)

    def _generate_listener_request(self):
        req = {}
        if self.is_sasl_enabled():
            if self.is_sasl_ldap_enabled():
                req["SASL"] = {
                    "protocol": "OAUTHBEARER",
                    "jaas.config": self._get_ldap_settings(
                        self.mds.get_bootstrap_servers()
                    ),
                    "confluent": {
                        "login.callback": "io.confluent.kafka.clients."
                                          "plugins.auth.token.TokenUser"
                                          "LoginCallbackHandler"
                    }
                }
            elif self.is_sasl_kerberos_enabled():
                raise KafkaCharmBaseFeatureNotImplementedError(
                    "Missing implementation of kerberos for Connect")
        req["is_public"] = False
        if self.is_sasl_enabled() and self.get_ssl_listener_truststore():
            req["secprot"] = "SASL_SSL"
        elif not self.is_sasl_enabled() and \
                self.get_ssl_listener_truststore():
            req["secprot"] = "SSL"
        elif self.is_sasl_enabled() and not \
                self.get_ssl_listener_truststore():
            req["secprot"] = "SASL_PLAINTEXT"
        else:
            req["secprot"] = "PLAINTEXT"
        if len(self.get_ssl_listener_cert()) > 0 and \
           len(self.get_ssl_listener_key()) > 0:
            req["cert"] = self.get_ssl_listener_cert()
        # Set the plaintext password
        if len(self.ks.listener_plaintext_pwd) == 0:
            self.ks.listener_plaintext_pwd = genRandomPassword(24)
        req["plaintext_pwd"] = self.ks.listener_plaintext_pwd
        self.listener.set_request(req)
        return req

    def on_listeners_relation_joined(self, event):
        self._on_config_changed(event)

    def on_listeners_relation_changed(self, event):
        try:
            self.listener.on_listener_relation_changed(event)
        except KafkaRelationBaseTLSNotSetError:
            logger.warning(
                "Detected some of the remote apps on listener relation "
                "but still waiting for setup on this unit.")
            # We need certs correctly configured to be able to set listeners
            # because certs are configured on other peers.
            # Defer this event until operator updates certificate info.
            self.model.unit.status = BlockedStatus(
                "Missing certificate info: listeners")
            event.defer()
            return
        self._on_config_changed(event)

    def on_certificates_relation_joined(self, event):
        self.certificates.on_tls_certificate_relation_joined(event)
        # Relation just joined, request certs for each of the relations
        # That will happen once. The certificates will be generated, then
        # it will trigger a -changed Event on certificates, which will
        # call the config-changed logic once again.
        # That way, the certificates will be added to the truststores
        # and shared across the other relations.

        # In case several relations shares the same set of IPs (spaces),
        # the last relation will get to set the certificate values.
        # Therefore, the order of the list below is relevant.
        for r in [self.listener,
                  self.sr]:
            self._cert_relation_set(None, r)
        self._on_config_changed(event)

    def on_certificates_relation_changed(self, event):
        self.certificates.on_tls_certificate_relation_changed(event)
        self._on_config_changed(event)

    def on_mds_relation_joined(self, event):
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
        """Recover the SSL certs and keys based on the relation"""

        prefix = ""
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

        if not relation or not self.certificates:
            raise KafkaRelationBaseTLSNotSetError(
                "_get_ssl relation {} or certificates"
                " not available".format(relation))
        try:
            certs = self.certificates.get_server_certs()
            c = certs[relation.binding_addr][ty]
            if ty == "cert":
                c = c + \
                    self.certificates.get_chain()
            logger.debug("SSL {} for {}"
                         " from tls-certificates: {}".format(ty, prefix, c))
        except (TLSCertificateDataNotFoundInRelationError,
                TLSCertificateRelationNotPresentError):
            # Certificates not ready yet, return empty
            return ""
        return c

    def _generate_keystores(self):
        ks = [[self.ks.ssl_cert, self.ks.ssl_key, self.ks.ks_password,
               self.get_ssl_cert, self.get_ssl_key, self.get_ssl_keystore],
              [self.ks.ssl_listener_cert, self.ks.ssl_listener_key,

               self.ks.ks_listener_pwd,
               self.get_ssl_listener_cert, self.get_ssl_listener_key,
               self.get_ssl_listener_keystore]]

        # Call the method from JavaCharmBase
        super()._generate_keystores(ks)

    def _get_service_name(self):
        if self.distro == 'confluent':
            self.service = 'confluent-schema-registry'
        elif self.distro == "apache":
            self.service = "schema-registry"
        return self.service

    def is_ssl_enabled(self):
        """Returns true if the API endpoint has the SSL enabled"""
        return len(self.get_ssl_cert()) > 0 and \
            len(self.get_ssl_key()) > 0

    def _render_schemaregistry_properties(self):
        """
        Render the schema-registry.properties:
        1) Read the options set using schema-registry-properties
        2) Set service options
        2.1) Set SSL options
        2.2) Set the schema-registry relation
        3) Set Listener-related information
        4) Set metadata and C3 information
        5) Render configs"""

        # 1) Read the options set using schema-registry-properties
        logger.info("Start to render schema-registry properties")
        sr_props = \
            yaml.safe_load(self.config.get(
                "schema-registry-properties", "")) or {}

        if self.distro == "confluent":
            sr_props["confluent.license.topic"] = \
                self.config.get("confluent_license_topic")

        sr_props["schema.registry.group.id"] = self.config["group-id"]
        sr_props["host.name"] = self.config["api_url"] if \
            len(self.config["api_url"]) > 0 \
            else get_hostname(self.sr.advertise_addr)
        sr_props["debug"] = "true" if self.config["debug"] else "false"
        sr_props["schema.registry.resource.extension.class"] = \
            self.config.get("resource-extension-class")
        sr_props["rest.servlet.initializor.classes"] = \
            self.config.get("rest-servlet-initializor-classes")

        # Authentication roles and method logic:
        auth_method = self.config.get(
            "rest_authentication_method", "").lower()
        # Manage authentication
        if auth_method == "none":
            # No authentication method
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

        # 2) Set services options
        # 2.1) Set SSL options
        # TODO(pguimaraes): recover extra certs set by actions
        extra_certs = []
        # If keystore value is set as empty, no certs are used.
        if len(self.get_ssl_keystore()) > 0:
            if len(self.get_ssl_key()) > 0 and len(self.get_ssl_cert()) > 0 and \
               len(self.get_ssl_truststore()):
                if len(self.get_ssl_keystore()) == 0:
                    raise SchemaRegistryCharmNotValidOptionSetError(
                        "keystore-path")
                sr_props["security.protocol"] = "SSL"
                sr_props["inter.instance.protocol"] = "https"
                if len(self.get_ssl_truststore()) > 0:
                    sr_props["ssl.truststore.location"] = \
                        self.get_ssl_truststore()
                    sr_props["ssl.truststore.password"] = \
                        self.ks.ts_password
                if len(self.get_ssl_keystore()) > 0:
                    sr_props["ssl.key.password"] = self.ks.ks_password
                    sr_props["ssl.keystore.location"] = self.get_ssl_keystore()
                    sr_props["ssl.keystore.password"] = self.ks.ks_password
                # Pass the TLS along
                if self.sr.relations:
                    self.sr.set_TLS_auth(
                        self.get_ssl_cert(),
                        self.get_ssl_truststore(),
                        self.ks.ts_password,
                        user=self.config["user"],
                        group=self.config["group"],
                        mode=0o640)
                else:
                    # We should consider the situation where connect
                    # is only exposed
                    # to the outside and no relations are set
                    ts_regenerate = \
                        self.config["regenerate-keystore-truststore"]
                    CreateTruststore(
                        self.get_ssl_truststore(),
                        self.ks.ts_password,
                        extra_certs,
                        ts_regenerate=ts_regenerate,
                        user=self.config["user"],
                        group=self.config["group"],
                        mode=0o640)
        else:
            sr_props["security.protocol"] = "PLAINTEXT"
            sr_props["inter.instance.protocol"] = "http"
        # If keystore option is set but certificates relation are not
        # yet configured, inter.instance.protocol will not exist within
        # sr_props. Therefore, assume http in these cases.
        sr_props["listeners"] = "{}://{}:{}".format(
            sr_props.get("inter.instance.protocol", "http"),
            self.config.get("listener", "0.0.0.0"),
            self.config.get("clientPort", 8081))

        # 2.2) Set the schema-registry relation
        # Manage Schema Registry relation
        if self.sr.relations:
            self.sr.schema_url = self._get_api_url(self.sr.advertise_addr)
            self.sr.set_converter(self.config["schema_converter"])
            self.sr.set_enhanced_avro_support(
                self.config.get("enhanced_avro_schema_support", ""))

        # 3) Set Listener-related information
        sr_props["kafkastore.topic"] = "_schemas"
        sr_props["kafkastore.topic.replication.factor"] = 3
        # Generate certs for listener relations
        # Only used if keystore exists
        if self.get_ssl_listener_keystore():
            if self.get_ssl_listener_truststore():
                self.listener.set_TLS_auth(
                    self.get_ssl_listener_cert(),
                    self.get_ssl_listener_truststore(),
                    self.ks.ts_listener_pwd,
                    user=self.config["user"],
                    group=self.config["group"],
                    mode=0o640)
        # Generate the request for listener
        self.model.unit.status = \
            MaintenanceStatus("Generate Listener settings")
        self._generate_listener_request()
        # Recover configs
        listener_opts = self.listener.generate_options(
            self.get_ssl_listener_keystore(),
            self.ks.ks_password,
            self.get_ssl_listener_truststore(),
            self.ks.ts_password,
            prefix="")
        if listener_opts:
            # Also add listener endpoints for producer and consumer
            sr_props = {**sr_props, **{
                "kafkastore.{}".format(k): v for k, v in listener_opts.items()
            }}
        else:
            logger.warning("get_bootstrap_data returned empty in "
                           "kafka_listeners")

        # 4) Set metadata and C3 information
        if self.distro == "confluent":
            mds_opts = self.mds.generate_configs(
                self.config["mds_public_key_path"],
                self.config.get("mds_user", ""),
                self.config.get("mds_password", "")
            )
            if mds_opts:
                sr_props = {**sr_props, **mds_opts}
        # There seems to be no need for the inspector listeners
        # which comes alongside C3. Will drop this relation for now.

        # 5) Render configs
        logger.debug("Options are: {}".format(",".join(sr_props)))
        render(source="schema-registry.properties.j2",
               target="/etc/schema-registry/schema-registry.properties",
               owner=self.config.get('user'),
               group=self.config.get("group"),
               perms=0o640,
               context={
                   "sr_props": sr_props
               })
        return sr_props

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
        return root_logger

    def _on_config_changed(self, event):
        """Runs the changes on configuration files.

        1) Check for any missing relations
        2) Check if TLS is set and configured correctly
        3) Prepare context: generate the configuration files
        4) Open ports
        5) Rerun loadbalancer configs"""

        # 1) Check for any missing relations
        if not self.listener.relations:
            self.model.unit.status = \
                BlockedStatus("Waiting for listener relation")
            # Abandon event as new relation -changed will trigger it again
            return

        self.model.unit.status = \
            MaintenanceStatus("generate certs and keys if needed")

        # Prepare context: generate the configuration files
        ctx = {}
        logger.debug("Running _generate_keystores()")
        self._generate_keystores()

        self.model.unit.status = \
            MaintenanceStatus("Render schema-registry.properties")
        logger.debug("Running render_schemaregistry_properties()")
        try:
            ctx["sr_props"] = self._render_schemaregistry_properties()
        except SchemaRegistryCharmNotValidOptionSetError:
            # Returning as we need to wait for a config change and that
            # will trigger a new event
            return
        except SchemaRegistryCharmMissingRelationError:
            # same reason as above, waiting for an add-relation
            return
        except KafkaListenerRelationNotSetError as e:
            logger.warn("Listener relation not ready yet: {}".format(str(e)))
            # It means there is not yet info on what the listener config
            # should look like.
            # Once that happens, listener relation will trigger a new -changed
            # event. We can abandon this one
            return
        self.model.unit.status = MaintenanceStatus("Render log4j properties")
        logger.debug("Running log4j properties renderer")
        ctx["logger"] = self._render_sr_log4j_properties()
        self.model.unit.status = \
            MaintenanceStatus("Render service override conf file")
        logger.debug("Render override.conf")
        ctx["svc_override"] = self.render_service_override_file(
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
        # 4) Open ports
        # 4.1) Close original ports
        for p in self.ks.ports:
            if p > 0:
                close_port(p)
        # 4.2) Open ports for the newly found listeners
        open_port(self.config.get("clientPort", 8081))
        self.ks.ports[0] = self.config.get("clientPort", 8081)

        # 5) Rerun load balancer config
        self._on_lb_provider_available(event)


if __name__ == "__main__":
    main(KafkaSchemaRegistryCharm)
