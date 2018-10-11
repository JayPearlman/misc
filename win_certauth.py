#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Jay Pearlman 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: win_certauth
version_added: '2.5'
short_description: Issues pending CA cert
description:
- Issues a requested pending cert from a Certificate Authority
options:
  caconfig:
    description:
    - A valid configuration string for the certification authority.
    - 'Example: COMPUTERNAME\CANAME'
    required: yes
  requestid:
    - Specifies the ID of the request to resubmit.
    - 'Example: 1234'
    required: yes
notes:
- The module requires the requestid to be in a pending state.
author:
- Jay Pearlman (@jaypearlman)
'''

EXAMPLES = r'''
- name: Approve / Issue pending certificate 1234
  win_certauth:
    caconfig: 'ca.contoso.com\MyCA'
    requestid: 1234
'''

RETURN = r'''
msg:
    description: changed
    returned: always
    type: boolean
    sample: True
disposition_of_request:
    description: The possible outcomes of the request
    returned: success
    type: string
    sample: The certificate was issued.
disposition_rc:
    description: The return code of the request
    returned: success
    type: int
    sample: 3
'''
