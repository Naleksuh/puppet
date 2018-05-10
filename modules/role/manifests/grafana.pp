# role: grafana
class role::grafana {
    include ::grafana

    ufw::allow { 'icinga http':
        proto => 'tcp',
        port  => '80',
    }

    ufw::allow { 'icinga https':
        proto => 'tcp',
        port  => '443',
    }

    ufw::allow { 'grafana tcp':
        proto => 'tcp',
        port  => 3000,
    }

    motd::role { 'role::grafana':
        description => 'central Grafana server',
    }
}
