#!powershell
# This file is part of Ansible
#
# Copyright 2018, Jay Pearlman 
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
# Code adapted from:
# https://social.technet.microsoft.com/Forums/windowsserver/en-US/7066c277-fd7c-4cae-add6-8ba4af9c48d1
# MSDN: https://msdn.microsoft.com/en-us/library/aa383250(v=vs.85).aspx

# WANT_JSON
# POWERSHELL_COMMON

Set-StrictMode -Version 2

$params = Parse-Args $args -supports_check_mode $true
$check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false
$caconfig = Get-AnsibleParam -obj $params -name "caconfig" -type "str" -failifempty $true
$requestid = Get-AnsibleParam -obj $params -name "requestid" -type "int" -failifempty $true

$result = @{
    changed = $false
}

Try {
    # Set up ICertAdmin2 object
    $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
} Catch {
    Fail-Json -obj $CertAdmin -message "Unable to instantiate ICertAdmin2 object."
}

if ($check_mode) {
    $result.changed = $true
} else {
    try {
        $result.disposition_rc = [int]($CertAdmin.ResubmitRequest($caconfig,$requestid))
        $result.disposition_of_request = switch ($result.disposition_rc) {
          0 {"The request was not completed."}
          1 {"The request failed."}
          2 {"The request was denied."}
          3 {"The certificate was issued."}
          4 {"The certificate was issued separately"}
          5 {"The request was taken under submission."}
          6 {"The certificate is revoked."}
          -2146877437 {"The request's current status does not allow this operation."}
        }
        $result.changed = $true
    } Catch {
      Fail-Json -obj $result -message ($_.Exception.ToString() -split '\r\n')[0]
    }
}

Exit-Json $result
