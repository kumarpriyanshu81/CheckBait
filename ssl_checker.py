import socket
import sys
from argparse import ArgumentParser
from datetime import datetime
from ssl import PROTOCOL_TLSv1
from OpenSSL import SSL

class SSLChecker:

    def get_cert(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        osobj = SSL.Context(PROTOCOL_TLSv1)
        sock.connect((host, int(port)))
        oscon = SSL.Connection(osobj, sock)
        oscon.set_tlsext_host_name(host.encode())
        oscon.set_connect_state()
        oscon.do_handshake()
        cert = oscon.get_peer_certificate()
        sock.close()
        return cert
    
    def get_cert_sans(self, x509cert):
        san = ''
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        san = san.replace(',', ';')
        return san

    def get_cert_info(self, host, cert):
        context = {}
        cert_subject = cert.get_subject()
        context['host'] = host
        context['issued_to'] = cert_subject.CN
        context['issued_o'] = cert_subject.O
        context['issuer_c'] = cert.get_issuer().countryName
        context['issuer_o'] = cert.get_issuer().organizationName
        context['issuer_ou'] = cert.get_issuer().organizationalUnitName
        context['issuer_cn'] = cert.get_issuer().commonName
        context['cert_sn'] = str(cert.get_serial_number())
        context['cert_sha1'] = cert.digest('sha1').decode()
        context['cert_alg'] = cert.get_signature_algorithm().decode()
        context['cert_ver'] = cert.get_version()
        context['cert_sans'] = self.get_cert_sans(cert)
        context['cert_exp'] = cert.has_expired()
        context['cert_valid'] = False if cert.has_expired() else True
        valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_from'] = valid_from.strftime('%Y-%m-%d')
        valid_till = datetime.strptime(cert.get_notAfter().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_till'] = valid_till.strftime('%Y-%m-%d')
        context['validity_days'] = (valid_till - valid_from).days
        now = datetime.now()
        context['days_left'] = (valid_till - now).days
        context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'],
                                           '%Y-%m-%d') - datetime.now()).days
        return context

    def print_status(self, host, context):
        print('Issued domain: {}'.format(context[host]['issued_to']))
        print('Issued to: {}'.format(context[host]['issued_o']))
        print('Issued by: {} ({})'.format(
            context[host]['issuer_o'], context[host]['issuer_c']))
        print('Valid from: {}'.format(context[host]['valid_from']))
        print('Valid to: {} ({} days left)'.format(
            context[host]['valid_till'], context[host]['valid_days_to_expire']))
        print('Validity days: {}'.format(context[host]['validity_days']))
        print('Certificate valid: {}'.format(context[host]['cert_valid']))
        print('Certificate S/N: {}'.format(context[host]['cert_sn']))
        print('Certificate SHA1 FP: {}'.format(context[host]['cert_sha1']))
        print('Certificate version: {}'.format(context[host]['cert_ver']))
        print('Certificate algorithm: {}'.format(
            context[host]['cert_alg']))
        print('Expired: {}'.format(context[host]['cert_exp']))
        print('Certificate SAN\'s: ')
        for san in context[host]['cert_sans'].split(';'):
            print(' \\_ {}'.format(san.strip()))
        print('\n')

    def show_result(self, user_args):
        context = {}
        hosts = user_args.hosts
        for host in hosts:
            host, port = self.filter_hostname(host)
            if host in context.keys():
                continue
            try:
                cert = self.get_cert(host, port)
                context[host] = self.get_cert_info(host, cert)
                context[host]['tcp_port'] = int(port)
                self.print_status(host, context)
            except Exception as error:
                print(f'\t[-]{host} Failed: {error}\n')
            except KeyboardInterrupt:
                print('Canceling script...\n')
                sys.exit(1)

    def filter_hostname(self, host):
        host = host.replace(
            'http://', '').replace('https://', '').replace('/', '')
        port = 443
        if ':' in host:
            host, port = host.split(':')

        return host, port

    def get_args(self):
    
        parser = ArgumentParser(prog='ssl_checker.py', add_help=False,
                                description="""Collects useful information about given host's SSL certificates.""")

        parser.add_argument('-H', '--host', dest='hosts', nargs='*',
                           required=False, help='Hosts as input separated by space')

        args = parser.parse_args()
        return args


if __name__ == '__main__':
    SSLCheckerObject = SSLChecker()
    SSLCheckerObject.show_result(SSLCheckerObject.get_args())
