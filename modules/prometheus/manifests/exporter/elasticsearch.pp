# Prometheus Elasticsearch query metrics exporter.
class prometheus::exporter::elasticsearch {
    ensure_packages([
        'python3-click',
        'python3-colorama',
        'python3-configobj',
        'python3-elasticsearch',
        'python3-prometheus-client',
    ])

    file { '/opt/prometheus-es-exporter_0.11.1-1_all.deb':
        ensure => present,
        source => 'puppet:///modules/prometheus/packages/prometheus-es-exporter_0.11.1-1_all.deb',
    }

    package { 'prometheus-es-exporter':
        ensure   => installed,
        provider => dpkg,
        source   => '/opt/prometheus-es-exporter_0.11.1-1_all.deb',
        require  => File['/opt/prometheus-es-exporter_0.11.1-1_all.deb'],
    }

    file { '/etc/prometheus-es-exporter':
        ensure  => directory,
        recurse => true,
        purge   => true,
        force   => true,
        owner   => 'root',
        group   => 'root',
        mode    => '0444',
        source  => 'puppet:///modules/prometheus/es_exporter',
        require => Package['prometheus-es-exporter'],
        notify  => Service['prometheus-es-exporter'],
    }

    # by default, prometheus-es-exporter exports cluster, index, and node metrics generated by prometheus-es-exporter
    # this unit override disables these metrics in prometheus-es-exporter
    systemd::service { 'prometheus-es-exporter':
        ensure   => present,
        content  => init_template('prometheus-es-exporter', 'systemd_override'),
        override => true,
        restart  => true,
    }

    $firewall_rules_str = join(
        query_facts('Class[Prometheus]', ['ipaddress', 'ipaddress6'])
        .map |$key, $value| {
            "${value['ipaddress']} ${value['ipaddress6']}"
        }
        .flatten()
        .unique()
        .sort(),
        ' '
    )
    ferm::service { 'prometheus es_exporter':
        proto  => 'tcp',
        port   => '9206',
        srange => "(${firewall_rules_str})",
    }
}
