# role: opensearch
class role::opensearch {
    $os_master = lookup('role::opensearch::master', {'default_value' => false})
    $os_data = lookup('role::opensearch::data', {'default_value' => false})
    $os_discovery = lookup('role::opensearch::discovery_host', {'default_value' => false})
    $os_master_hosts = lookup('role::opensearch::master_hosts', {'default_value' => undef})

    include ::java

    if $os_master {
        include prometheus::exporter::elasticsearch
    }

    class { 'opensearch::repo':
        version => '2.x',
    }

    class { 'opensearch':
        config      => {
            'cluster.initial_master_nodes'                          => $os_master_hosts,
            'discovery.seed_hosts'                                  => $os_discovery,
            'cluster.name'                                          => 'miraheze-general',
            'node.master'                                           => $os_master,
            'node.data'                                             => $os_data,
            'network.host'                                          => $::fqdn,
            'plugins.security.ssl.http.enabled'                     => true,
            'plugins.security.ssl.http.pemkey_filepath'             => '/etc/opensearch/ssl/wildcard.miraheze.org-2020-2.key',
            'plugins.security.ssl.http.pemcert_filepath'            => '/etc/opensearch/ssl/wildcard.miraheze.org-2020-2.crt',
            'plugins.security.ssl.http.pemtrustedcas_filepath'      => '/etc/opensearch/ssl/Sectigo.crt',
            'plugins.security.ssl.transport.pemkey_filepath'        => '/etc/opensearch/ssl/wildcard.miraheze.org-2020-2.key',
            'plugins.security.ssl.transport.pemcert_filepath'       => '/etc/opensearch/ssl/wildcard.miraheze.org-2020-2.crt',
            'plugins.security.ssl.transport.pemtrustedcas_filepath' => '/etc/opensearch/ssl/Sectigo.crt',
        },
        version     => '2.5.0',
        manage_repo => true,
        jvm_options => [ '-Xms2g', '-Xmx2g' ],
        templates   => {
            'graylog-internal' => {
                'source' => 'puppet:///modules/role/opensearch/index_template.json'
            }
        }
    }

    # Contains everything needed to update the opensearch security index
    # to apply any config changes to the index.
    # This is required to be run everytime the config changes.
    file { '/usr/local/bin/opensearch-security':
        ensure => present,
        mode   => '0755',
        source => 'puppet:///modules/role/opensearch/bin/opensearch-security.sh',
    }

    # On the first install you will have to run /usr/local/bin/opensearch-security manually to create
    # the index.
    # File can be found at https://repo1.maven.org/maven2/org/opensearch/plugin/opensearch-security/
    opensearch::plugin { 'opensearch-security':
        source => 'puppet:///private/opensearch/opensearch-security-2.5.0.0.zip',
    }

    file {
        require => Opensearch::Plugin['opensearch-security'],
        notify  => $opensearch::_notify_service,
        owner   => $opensearch::opensearch_user,
        group   => $opensearch::opensearch_group,
        "${$opensearch::configdir}/opensearch-security/config.yml":
            ensure => present,
            source => 'puppet:///modules/role/opensearch/config.yml';
        "${$opensearch::configdir}/opensearch-security/roles_mapping.yml":
            ensure => present,
            source => 'puppet:///modules/role/opensearch/roles_mapping.yml';
        "${$opensearch::configdir}/opensearch-security/roles.yml":
            ensure => present,
            source => 'puppet:///modules/role/opensearch/roles.yml';
    }

    file { '/etc/opensearch/ssl':
        ensure => directory,
        owner  => $opensearch::opensearch_user,
        group  => $opensearch::opensearch_group,
    }

    ssl::wildcard { 'opensearch wildcard':
        ssl_cert_path             => '/etc/opensearch/ssl',
        ssl_cert_key_private_path => '/etc/opensearch/ssl',
        require                   => File['/etc/opensearch/ssl']
    }

    if $os_master {
        nginx::site { 'opensearch.miraheze.org':
            ensure  => present,
            source  => 'puppet:///modules/role/opensearch/nginx.conf',
            monitor => false,
        }

        $firewall_rules_str = join(
            query_facts('Class[Role::Mediawiki] or Class[Role::Icinga2] or Class[Role::Graylog] or Class[Role::Opensearch]', ['ipaddress6'])
            .map |$key, $value| {
                $value['ipaddress6']
            }
            .flatten()
            .unique()
            .sort(),
            ' '
        )

        ferm::service { 'opensearch ssl':
            proto  => 'tcp',
            port   => '443',
            srange => "(${firewall_rules_str})",
        }
    }

    $firewall_os_nodes = join(
        query_facts('Class[Role::Opensearch]', ['ipaddress6'])
        .map |$key, $value| {
            $value['ipaddress6']
        }
        .flatten()
        .unique()
        .sort(),
        ' '
    )
    ferm::service { 'opensearch data nodes to master':
        proto  => 'tcp',
        port   => '9200',
        srange => "(${firewall_os_nodes})",
    }

    ferm::service { 'opensearch master access data nodes 9200 port':
        proto  => 'tcp',
        port   => '9300',
        srange => "(${firewall_os_nodes})",
    }

    motd::role { 'role::opensearch':
        description => 'opensearch server',
    }
}
