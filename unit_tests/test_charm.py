# Copyright 2021 pguimaraes
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from mock import patch
from mock import PropertyMock

import src.charm as charm
from ops.testing import Harness

import wand.contrib.java as java
import wand.apps.kafka as kafka
import wand.apps.relations.kafka_mds as kafka_mds
import wand.apps.relations.kafka_listener as kafka_listener
import wand.apps.relations.kafka_schema_registry as kafka_sr

from loadbalancer_interface import LBProvider

TO_PATCH_LINUX = [
    "userAdd",
    "groupAdd"
]

TO_PATCH_FETCH = [
    'apt_install',
    'apt_update',
    'add_source'
]

TO_PATCH_HOST = [
    'service_resume',
    'service_running',
    'service_restart',
    'service_reload'
]

CONFIG_CHANGED="""
authentication.roles=**
confluent.license.topic=_confluent-license
confluent.metadata.basic.auth.user.info=schema_registry:password123
confluent.metadata.bootstrap.server.urls=https://ansiblebroker1.example.com:8090
confluent.metadata.http.auth.credentials.provider=BASIC
confluent.schema.registry.auth.mechanism=JETTY_AUTH
confluent.schema.registry.authorizer.class=io.confluent.kafka.schemaregistry.security.authorizer.rbac.RbacAuthorizer
debug=false
host.name=ansibleschemaregistry1.example.com
inter.instance.protocol=https
kafkastore.bootstrap.servers=ansiblebroker1.example.com:9092
kafkastore.sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required username="schema_registry" password="password123" metadataServerUrls="https://ansiblebroker1.example.com:8090";
kafkastore.sasl.login.callback.handler.class=io.confluent.kafka.clients.plugins.auth.token.TokenUserLoginCallbackHandler
kafkastore.sasl.mechanism=OAUTHBEARER
kafkastore.security.protocol=SASL_SSL
kafkastore.ssl.truststore.location=/var/ssl/private/schema_registry.truststore.jks
kafkastore.ssl.truststore.password=confluentkeystorestorepass
kafkastore.topic=_schemas
kafkastore.topic.replication.factor=3
listeners=https://0.0.0.0:8081
public.key.path=/var/ssl/private/public.pem
rest.servlet.initializor.classes=io.confluent.common.security.jetty.initializer.InstallBearerOrBasicSecurityHandler
schema.registry.group.id=schema-registry
schema.registry.resource.extension.class=io.confluent.kafka.schemaregistry.security.SchemaRegistrySecurityResourceExtension
security.protocol=SSL
ssl.key.password=confluentkeystorestorepass
ssl.keystore.location=/var/ssl/private/schema_registry.keystore.jks
ssl.keystore.password=confluentkeystorestorepass
ssl.truststore.location=/var/ssl/private/schema_registry.truststore.jks
ssl.truststore.password=confluentkeystorestorepass""" # noqa


class TestCharm(unittest.TestCase):
    maxDiff = None

    def _patch(self, obj, method):
        _m = patch.object(obj, method)
        mock = _m.start()
        self.addCleanup(_m.stop)
        return mock

    def _simulate_render(self, ctx=None, templ_file=""):
        import jinja2
        env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
        templ = env.get_template(templ_file)
        doc = templ.render(ctx)
        return doc

    def setUp(self):
        super().setUp()

    @patch.object(charm.LBProvider, "is_available")
    @patch.object(charm, "close_port")
    @patch.object(kafka, "open_port")
    @patch.object(charm, "open_port")
    @patch.object(kafka.KafkaJavaCharmBasePrometheusMonitorNode,
                  'advertise_addr', new_callable=PropertyMock)
    def test_config_changed_missing_listeners(self,
                                              mock_prometheus_advert_addr,
                                              mock_open_port,
                                              mock_kafka_open_port,
                                              mock_close_port,
                                              mock_lb_available):
        mock_lb_available.return_value = False
        self.harness = Harness(charm.KafkaSchemaRegistryCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        connect = self.harness.charm
        self.harness.update_config({
            "user": "test",
            "group": "test"
        })
        self.assertEqual(
            connect.unit.status.message, "Waiting for listener relation")

    @patch.object(charm.LBProvider, "is_available")
    @patch.object(charm, "close_port")
    @patch.object(kafka, "open_port")
    @patch.object(charm, "open_port")
    @patch.object(kafka.KafkaJavaCharmBasePrometheusMonitorNode,
                  'advertise_addr', new_callable=PropertyMock)
    @patch.object(kafka_sr.KafkaSchemaRegistryProvidesRelation,
                  "schema_url", new_callable=PropertyMock)
    @patch.object(kafka_listener.KafkaListenerRequiresRelation,
                  "get_bootstrap_data")
    @patch.object(charm.KafkaSchemaRegistryCharm,
                  "render_service_override_file",
                  new_callable=PropertyMock)
    # Mock the password generation method and replace for the same pwd
    @patch.object(java, "genRandomPassword")
    @patch.object(charm, "genRandomPassword")
    @patch.object(charm.KafkaSchemaRegistryCharm, "_generate_keystores")
    @patch.object(charm.KafkaSchemaRegistryCharm, "get_ssl_key")
    @patch.object(charm.KafkaSchemaRegistryCharm, "get_ssl_cert")
    @patch.object(charm, "service_running")
    @patch.object(charm, "service_reload")
    @patch.object(charm, "service_restart")
    @patch.object(charm, "service_resume")
    @patch.object(charm.KafkaSchemaRegistryCharm, "_get_ssl")
    @patch.object(kafka_sr.KafkaSchemaRegistryProvidesRelation,
                  "advertise_addr",
                  new_callable=PropertyMock)
    # Ignore this method since it just copies the key content to the file
    @patch.object(kafka_mds.KafkaMDSRequiresRelation, "get_public_key",
                  new_callable=PropertyMock)
    # Needed for the host.name parameter
    @patch.object(charm, "get_hostname")
    # Needed for the host.name parameter
    @patch.object(kafka, "get_hostname")
    # No REST relation,which should trigger the manual creation
    @patch.object(charm, "CreateTruststore")
    # Ignore any set_TLS_auth calls as it is not relevant for this check
    @patch.object(kafka_listener.KafkaListenerRequiresRelation,
                  "set_TLS_auth",
                  new_callable=PropertyMock)
    @patch.object(charm, "render")
    def test_config_changed_no_conn_rel(self,
                                        mock_render,
                                        mock_set_tls_auth,
                                        mock_create_ts,
                                        mock_get_hostname_kafka,
                                        mock_get_hostname,
                                        mock_get_public_key,
                                        mock_advertise_addr,
                                        mock_get_ssl,
                                        mock_svc_resume,
                                        mock_svc_restart,
                                        mock_svc_reload,
                                        mock_svc_running,
                                        mock_get_ssl_cert,
                                        mock_get_ssl_key,
                                        mock_gen_jks,
                                        mock_gen_pwd,
                                        mock_java_gen_pwd,
                                        mock_render_svc_override,
                                        mock_bootstrap_data,
                                        mock_sr_url_setter,
                                        mock_prometheus_advert_addr,
                                        mock_open_port,
                                        mock_kafka_open_port,
                                        mock_close_port,
                                        mock_lb_available):
        mock_lb_available.return_value = False
        mock_prometheus_advert_addr.return_value = "192.168.200.200"
        mock_get_ssl_cert.return_value = "a"
        mock_get_ssl_key.return_value = "a"
        mock_gen_pwd.return_value = "confluentkeystorestorepass"
        mock_java_gen_pwd.return_value = "confluentkeystorestorepass"
        mock_get_hostname.return_value = "ansibleschemaregistry1.example.com"
        mock_get_hostname_kafka.return_value = mock_get_hostname.return_value
        self.harness = Harness(charm.KafkaSchemaRegistryCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        sr = self.harness.charm
        #
        # CONFIG
        #
        self.harness.update_config({
            "user": "test",
            "group": "test",
            "keystore-path": "/var/ssl/private/schema_registry.keystore.jks",
            "truststore-path": "/var/ssl/private/schema_registry.truststore.jks",
            "listener-keystore-path": "", # noqa
            "listener-truststore-path": "/var/ssl/private/schema_registry.truststore.jks", # noqa
            "sasl-protocol": "LDAP",
            "mds_public_key_path": "/var/ssl/private/public.pem",
            "mds_user": "schema_registry",
            "mds_password": "password123",
            "confluent_license_topic": "_confluent-license"
        })
        # MDS RELATION SETUP
        mds_id = self.harness.add_relation("mds", "broker")
        self.harness.add_relation_unit(mds_id, "broker/0")
        self.harness.update_relation_data(mds_id, "broker", {
            "public-key": "abc"
        })
        self.harness.update_relation_data(mds_id, "broker/0", {
            "mds_url": "https://ansiblebroker1.example.com:8090"
        })
        # LISTENER RELATION SETUP
        lst_id = self.harness.add_relation("listeners", "broker")
        self.harness.add_relation_unit(lst_id, 'broker/0')
        self.harness.update_relation_data(lst_id, 'broker/0', {
            "bootstrap-data": '''{ "kafka_schema_registry": {
                "bootstrap_server": "ansiblebroker1.example.com:9092"
            }}'''
        })
        # Override the bootstrap_data method to return the request
        # generated for the listener.
        # 1st, call the actual _generate_listener_request(),
        # to push data onto the relations
        mock_bootstrap_data.return_value = sr._generate_listener_request()
        print("This is the bootstrap data value", sr.listener.get_bootstrap_data())
        # CONFLUENT CENTER RELATION SETUP
        c3_id = self.harness.add_relation("c3", "c3")
        self.harness.add_relation_unit(c3_id, 'c3/0')
        self.harness.update_relation_data(c3_id, 'c3/0', {
            "bootstrap-server": "ansiblebroker1.example.com:9092"
        })
        sr_props = sr._render_schemaregistry_properties()
        print(sr_props)
        # Check if CreateTruststore was called because
        # of missing schema registry relation
        mock_create_ts.assert_called()
        simulate_render = self._simulate_render(
            ctx={
                "sr_props": sr_props
            },
            templ_file='schema-registry.properties.j2')
        simulate_render = "\n".join(sorted(simulate_render.split("\n")))
        print(simulate_render)
        self.assertSetEqual(
            set(CONFIG_CHANGED.split("\n")),
            set(simulate_render.split("\n")))

    @patch.object(charm.LBProvider, "is_available")
    @patch.object(charm, "close_port")
    @patch.object(kafka, "open_port")
    @patch.object(charm, "open_port")
    @patch.object(kafka.KafkaJavaCharmBasePrometheusMonitorNode,
                  'advertise_addr', new_callable=PropertyMock)
    # Patch methods to evaluate relation is correctly set
    @patch.object(kafka_sr.KafkaSchemaRegistryProvidesRelation,
                  "set_enhanced_avro_support")
    @patch.object(kafka_sr.KafkaSchemaRegistryProvidesRelation,
                  "set_converter")
    @patch.object(kafka_sr.KafkaSchemaRegistryProvidesRelation,
                  "schema_url", new_callable=PropertyMock)
    #####
    @patch.object(kafka_sr.KafkaSchemaRegistryProvidesRelation,
                  "set_TLS_auth")
    @patch.object(kafka_listener.KafkaListenerRequiresRelation,
                  "get_bootstrap_data")
    @patch.object(charm.KafkaSchemaRegistryCharm,
                  "render_service_override_file",
                  new_callable=PropertyMock)
    # Mock the password generation method and replace for the same pwd
    @patch.object(java, "genRandomPassword")
    @patch.object(charm, "genRandomPassword")
    @patch.object(charm.KafkaSchemaRegistryCharm, "_generate_keystores")
    @patch.object(charm.KafkaSchemaRegistryCharm, "get_ssl_key")
    @patch.object(charm.KafkaSchemaRegistryCharm, "get_ssl_cert")
    @patch.object(charm, "service_running")
    @patch.object(charm, "service_reload")
    @patch.object(charm, "service_restart")
    @patch.object(charm, "service_resume")
    @patch.object(charm.KafkaSchemaRegistryCharm, "_get_ssl")
    @patch.object(kafka_sr.KafkaSchemaRegistryProvidesRelation,
                  "advertise_addr",
                  new_callable=PropertyMock)
    # Ignore this method since it just copies the key content to the file
    @patch.object(kafka_mds.KafkaMDSRequiresRelation, "get_public_key",
                  new_callable=PropertyMock)
    # Needed for the host.name parameter
    @patch.object(charm, "get_hostname")
    # Needed for the host.name parameter
    @patch.object(kafka, "get_hostname")
    # No REST relation,which should trigger the manual creation
    @patch.object(charm, "CreateTruststore")
    # Ignore any set_TLS_auth calls as it is not relevant for this check
    @patch.object(kafka_listener.KafkaListenerRequiresRelation,
                  "set_TLS_auth",
                  new_callable=PropertyMock)
    @patch.object(charm, "render")
    def test_config_changed_set_sr_rel(self,
                                       mock_render,
                                       mock_set_tls_auth,
                                       mock_create_ts,
                                       mock_get_hostname_kafka,
                                       mock_get_hostname,
                                       mock_get_public_key,
                                       mock_advertise_addr,
                                       mock_get_ssl,
                                       mock_svc_resume,
                                       mock_svc_restart,
                                       mock_svc_reload,
                                       mock_svc_running,
                                       mock_get_ssl_cert,
                                       mock_get_ssl_key,
                                       mock_gen_jks,
                                       mock_gen_pwd,
                                       mock_java_gen_pwd,
                                       mock_render_svc_override,
                                       mock_bootstrap_data,
                                       mock_sr_rel_tls_auth,
                                       mock_sr_url_setter,
                                       mock_converter_setter,
                                       mock_sr_enchanced_avro,
                                       mock_prometheus_advert_addr,
                                       mock_open_port,
                                       mock_kafka_open_port,
                                       mock_close_port,
                                       mock_lb_available):
        mock_lb_available.return_value = False
        mock_prometheus_advert_addr.return_value = "192.168.200.200"
        mock_get_ssl_cert.return_value = "a"
        mock_get_ssl_key.return_value = "a"
        mock_gen_pwd.return_value = "confluentkeystorestorepass"
        mock_java_gen_pwd.return_value = "confluentkeystorestorepass"
        mock_get_hostname.return_value = "ansibleschemaregistry1.example.com"
        mock_get_hostname_kafka.return_value = mock_get_hostname.return_value
        self.harness = Harness(charm.KafkaSchemaRegistryCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        sr = self.harness.charm
        #
        # CONFIG
        #
        self.harness.update_config({
            "user": "test",
            "group": "test",
            "keystore-path": "/var/ssl/private/schema_registry.keystore.jks",
            "truststore-path": "/var/ssl/private/schema_registry.truststore.jks",
            "listener-keystore-path": "", # noqa
            "listener-truststore-path": "/var/ssl/private/schema_registry.truststore.jks", # noqa
            "sasl-protocol": "LDAP",
            "mds_public_key_path": "/var/ssl/private/public.pem",
            "mds_user": "schema_registry",
            "mds_password": "password123",
            "confluent_license_topic": "_confluent-license",
            "schema_converter": "test_converter",
            "enhanced_avro_schema_support": "true"
        })
        # MDS RELATION SETUP
        mds_id = self.harness.add_relation("mds", "broker")
        self.harness.add_relation_unit(mds_id, "broker/0")
        self.harness.update_relation_data(mds_id, "broker", {
            "public-key": "abc"
        })
        self.harness.update_relation_data(mds_id, "broker/0", {
            "mds_url": "https://ansiblebroker1.example.com:8090"
        })
        # LISTENER RELATION SETUP
        lst_id = self.harness.add_relation("listeners", "broker")
        self.harness.add_relation_unit(lst_id, 'broker/0')
        self.harness.update_relation_data(lst_id, 'broker/0', {
            "bootstrap-data": '''{ "kafka_schema_registry": {
                "bootstrap_server": "ansiblebroker1.example.com:9092"
            }}'''
        })
        # SCHEMA REGISTRY RELATION SETUP
        sr_id = self.harness.add_relation("schemaregistry", "target")
        self.harness.add_relation_unit(sr_id, 'target/0')
        # Override the bootstrap_data method to return the request
        # generated for the listener.
        # 1st, call the actual _generate_listener_request(),
        # to push data onto the relations
        mock_bootstrap_data.return_value = sr._generate_listener_request()
        print("This is the bootstrap data value", sr.listener.get_bootstrap_data())
        # CONFLUENT CENTER RELATION SETUP
        c3_id = self.harness.add_relation("c3", "c3")
        self.harness.add_relation_unit(c3_id, 'c3/0')
        self.harness.update_relation_data(c3_id, 'c3/0', {
            "bootstrap-server": "ansiblebroker1.example.com:9092"
        })
        sr._render_schemaregistry_properties()
        # Check if CreateTruststore was called because
        # of missing schema registry relation
        mock_sr_rel_tls_auth.assert_called()
        mock_sr_url_setter.assert_called_with(
            "https://ansibleschemaregistry1.example.com:8081")
        mock_converter_setter.assert_called_with("test_converter")
        mock_sr_enchanced_avro.assert_called_with("true")
