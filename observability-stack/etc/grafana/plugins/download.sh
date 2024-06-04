#!/bin/bash
set -ex

VM_DS_PATH='/var/lib/grafana/plugins/victorialogs-datasource'
PLUGIN_PATH='/var/lib/grafana/plugins'

if [[ -f ${VM_DS_PATH}/plugin.json ]]; then
    ver=$(cat ${VM_DS_PATH}/plugin.json)
    if [[ ! -z "$ver" ]]; then
    exit
    fi
fi

rm -rf ${VM_DS_PATH}/* || true
mkdir -p ${VM_DS_PATH}

export LATEST_VERSION=$(curl https://api.github.com/repos/VictoriaMetrics/victorialogs-datasource/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1); \
curl -L https://github.com/VictoriaMetrics/victorialogs-datasource/releases/download/${LATEST_VERSION}/victorialogs-datasource-${LATEST_VERSION}.tar.gz -o ${PLUGIN_PATH}/victorialogs-plugin.tar.gz && \
tar -xzf ${PLUGIN_PATH}/victorialogs-plugin.tar.gz -C ${PLUGIN_PATH}
rm ${PLUGIN_PATH}/victorialogs-plugin.tar.gz


ver=$(curl -s https://api.github.com/repos/VictoriaMetrics/grafana-datasource/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
curl -L https://github.com/VictoriaMetrics/grafana-datasource/releases/download/$ver/victoriametrics-datasource-$ver.tar.gz -o ${PLUGIN_PATH}/victoriametrics-plugin.tar.gz
tar -xzf ${PLUGIN_PATH}/victoriametrics-plugin.tar.gz -C ${PLUGIN_PATH}
rm ${PLUGIN_PATH}/victoriametrics-plugin.tar.gz