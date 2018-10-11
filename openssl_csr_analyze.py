#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2018, Jay Pearlman based on code
# originally from Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: openssl_csr_analyze
author: "Jay Pearlman"
version_added: "2.4"
short_description: Analyze OpenSSL Certificate Signing Request (CSR)
description:
    - "This module allows one to analyze OpenSSL certificate signing requests.
       It uses the pyOpenSSL python library to interact with openssl."
requirements:
    - "python-pyOpenSSL"
options:
    path:
        required: path OR csrdata
        description:
            - Name of the OpenSSL certificate signing request file
    csrdata:
        required: path OR csrdata
        description:
            - PEM encoded text block of OpenSSL certificate signing request
'''


EXAMPLES = '''
# Analyze an OpenSSL Certificate Signing Request file
- openssl_csr_analyze:
    path: /etc/ssl/csr/www.ansible.com.csr
    register: result

# Analyze an OpenSSL Certificate Signing Request PEM Block
- openssl_csr_analyze:
    csrdata: |
            -----BEGIN CERTIFICATE REQUEST-----
            MIIDOjCCAiICAQAwgYIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEMMAoG
            FbZ7nZN8lYEHLtJ6YHA=
            -----END CERTIFICATE REQUEST-----
    register: result
'''


RETURN = '''
key:
    description: A dictionary of the public key attached to the CSR
    returned: success
    type: dict
    sample: {'size', 'type'}
key->size:
    description: Bit size of public key
    returned: success
    type: integer
    sample: 2048
key->type:
    description: Type of public key
    returned: success
    type: string
    sample: 'RSA'
keyMin:
    description: Does the key meet minimum standards
    returned: success
    type: bool
    sample: True
subject:
    description: A dictionary of the subject attached to the CSR
    returned: success
    type: dict
    sample: {'CN': 'www.ansible.com', 'O': 'Ansible'}
subjectAltName:
    description: A dictionary of the alternative names attached to the CSR
    returned: success
    type: dict
    sample: {'DNS', 'IP Address'}
subjectAltName->DNS:
    description: Alternative DNS names
    returned: success
    type: list
    sample: [ 'www.ansible.com', 'ansible.com' ]
subjectAltName->IP Address:
    description: Alternative IP Addresses
    returned: success
    type: list
    sample: [ '10.2.3.4' ]
subjectvalid:
    description: Subject validity for complete C,CN,L,O,OU,ST
    returned: success
    type: bool
    sample: True
'''

import os

from ansible.module_utils import crypto as crypto_utils
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

try:
    import OpenSSL
    from OpenSSL import crypto
    from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

except ImportError:
    pyopenssl_found = False
else:
    pyopenssl_found = True


class CertificateSigningRequestError(crypto_utils.OpenSSLObjectError):
    '''Built in object'''
    pass


class CertificateSigningRequest(object):
    '''Custom CSR object'''

    # pylint: disable=too-many-instance-attributes

    def __init__(self, module):

        self.path = module.params['path']
        self.csrdata = module.params['csrdata']
        self.changed = False

        self.subject = {
            'C': '',
            'ST': '',
            'L': '',
            'O': '',
            'OU': '',
            'CN': '',
        }
        self.subjectvalid = True
        self.keymin = False
        self.subjectAltName = {}
        self.key = {}

    def check(self, module):
        """Ensure the resource is in its desired state."""

        def _get_subject(csr):
            subject = csr.get_subject()
            components = dict(subject.get_components())
            for sub_key, sub_val in components.items():
                self.subject[sub_key] = sub_val
            for val in self.subject.values():
                if val == '':
                    self.subjectvalid = False

        def _get_san(csr):
            extensions = csr.get_extensions()
            for ext in extensions:
                if ext.get_short_name() == b"subjectAltName":
                    for altname in str(ext).split(','):
                        altname_data = altname.strip().split(':')
                        if altname_data[0] not in self.subjectAltName:
                            self.subjectAltName[altname_data[0]] = []
                        self.subjectAltName[altname_data[0]].append(altname_data[1])

        def _get_key(csr):
            key = csr.get_pubkey()
            if key.type() == OpenSSL.crypto.TYPE_RSA:
                key_type = 'RSA'
            elif key.type() == OpenSSL.crypto.TYPE_DSA:
                key_type = 'DSA'
            elif key.type() == 408:
                key_type = 'EC'
            else:
                key_type = 'Unknown'

            self.key = {
                'type': key_type,
                'size': key.bits(),
            }

            # Minimums are being defined as 4096 for RSA/DSA & 384 for EC
            if (key_type == 'RSA' or key_type == 'DSA') and key.bits() >= 4096:
                self.keymin = True
            elif key_type == 'EC' and key.bits() >= 384:
                self.keymin = True

        if module.params['path']:
            csr = crypto_utils.load_certificate_request(self.path)
        else:
            try:
                csr = load_certificate_request(FILETYPE_PEM, self.csrdata)
            except (OpenSSL.crypto.Error) as exc:
                module.fail_json(msg=to_native(exc))

        _get_subject(csr)
        _get_key(csr)
        _get_san(csr)

    def dump(self):
        '''Serialize the object into a dictionary.'''

        result = {
            'filename': self.path,
            'subject': self.subject,
            'subjectvalid': self.subjectvalid,
            'subjectAltName': self.subjectAltName,
            'key': self.key,
            'keyMin': self.keymin,
            'changed': self.changed
        }

        return result


def main():
    '''Main'''
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(required=False, type='path'),
            csrdata=dict(require=False, type='str'),
        ),
        supports_check_mode=True,
        required_one_of=[['path', 'csrdata']],
    )

    if not pyopenssl_found:
        module.fail_json(msg='the python pyOpenSSL module is required')

    try:
        getattr(crypto.X509Req, 'get_extensions')
    except AttributeError:
        module.fail_json(msg='You need to have PyOpenSSL>=0.15 to generate CSRs')

    if module.params['path']:
        base_dir = os.path.dirname(module.params['path'])
        if not os.path.isdir(base_dir):
            module.fail_json(name=base_dir, msg='The directory %s does not exist \
            or the file is not a directory' % base_dir)

    csr = CertificateSigningRequest(module)
    csr.check(module)

    result = csr.dump()

    module.exit_json(**result)


if __name__ == "__main__":
    main()
