import ssl
import socket
import re
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.extensions import ExtensionNotFound


DOMAIN_VALIDATED_POLICY_OID = "2.23.140.1.2.1"
ORGANIZATION_VALIDATED_POLICY_OID = "2.23.140.1.2.2"


def get_chrome_root_ca_ev_policy_oids_from_source():
	url = "https://raw.githubusercontent.com/chromium/chromium/f18e79d901f56154f80eea1e2218544285e62623/net/cert/ev_root_ca_metadata.cc"
	r = requests.get(url)
	matches = re.findall(u'\"[0-9.]+\"', r.text)
	oids = list(set([str(x).replace('"','') for x in matches]))
	return oids

def get_certificate_validation_type(hostname, port=443, ev_policy_oids=get_chrome_root_ca_ev_policy_oids_from_source()):
	validation_type = None
	socket.setdefaulttimeout(3)
	policy_oids = []

	try:
		pem = ssl.get_server_certificate((hostname, port), ssl_version=ssl.PROTOCOL_TLSv1_2).encode('utf-8')
	except Exception as e:
		print str(e)
		return validation_type	

	cert = x509.load_pem_x509_certificate(pem, default_backend())

	try:
		cert_policies = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CERTIFICATE_POLICIES).value
	except ExtensionNotFound:
		cert_policies = []

	for cert_policy in cert_policies:
		policy_oids.append(cert_policy.policy_identifier.dotted_string)

	if DOMAIN_VALIDATED_POLICY_OID in policy_oids:
		validation_type = "DV"
	elif ORGANIZATION_VALIDATED_POLICY_OID in policy_oids:
		validation_type = "OV"
	elif any(x in policy_oids for x in ev_policy_oids):
		validation_type = "EV"
	else:
		validation_type = "UN"

	return validation_type


ev_oids = get_chrome_root_ca_ev_policy_oids_from_source()
print get_certificate_validation_type(hostname='www.chase.com', ev_policy_oids=ev_oids)
print get_certificate_validation_type(hostname='www.bankofamerica.com', ev_policy_oids=ev_oids)
print get_certificate_validation_type(hostname='www.visa.com', ev_policy_oids=ev_oids)
print get_certificate_validation_type(hostname='www.google.com', ev_policy_oids=ev_oids)
