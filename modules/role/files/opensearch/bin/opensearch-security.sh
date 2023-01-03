#! /bin/bash

bash /usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/opensearch/opensearch-security \
  -rev -h es131.miraheze.org \
  -cert /etc/opensearch/ssl/wildcard.miraheze.org-2020-2.crt \
  -key /etc/opensearch/ssl/wildcard.miraheze.org-2020-2-key.pem \
  -cacert /etc/opensearch/ssl/Sectigo.crt
