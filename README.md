#env
# Networking
API_PORT=8080

# Images (pin versions here if you want)
WPSCAN_IMAGE=wpscanteam/wpscan
NIKTO_IMAGE=frapsoft/nikto
NUCLEI_IMAGE=projectdiscovery/nuclei:latest
ZAP_IMAGE=zaproxy/zap-stable
TESTSSL_IMAGE=drwetter/testssl.sh
WHATWEB_IMAGE=urbanadventurer/whatweb
DROOPESCAN_IMAGE=trolldbois/droopescan
JOOMSCAN_IMAGE=owasp/joomscan

# Tokens / templates
WPVULNDB_API_TOKEN=
NUCLEI_TEMPLATES=/root/nuclei-templates
NUCLEI_UPDATE_ON_START=true
