# encoding: UTF-8

control 'V-219317' do
  title "The Ubuntu operating system must implement smart card logins for
multifactor authentication for access to accounts."
  desc  "Without the use of multifactor authentication, the ease of access to
privileged functions is greatly increased.

    Multifactor authentication requires using two or more factors to achieve
authentication.

    Factors include:
    1) something a user knows (e.g., password/PIN);
    2) something a user has (e.g., cryptographic identification device, token);
and
    3) something a user is (e.g., biometric).

    A privileged account is defined as an information system account with
authorizations of a privileged user.

    Network access is defined as access to an information system by a user (or
a process acting on behalf of a user) communicating through a network (e.g.,
local area network, wide area network, or the Internet).

    The DoD CAC with DoD-approved PKI is an example of multifactor
authentication.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system uses multifactor authentication for
local access to accounts.

    Check that the \"pam_pkcs11.so\" option is configured in the
\"/etc/pam.d/common-auth\" file with the following command:

    # grep pam_pkcs11.so /etc/pam.d/common-auth
    auth [success=2 default=ignore] pam_pkcs11.so

    If \"pam_pkcs11.so\" is not set in \"/etc/pam.d/common-auth\", this is a
finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to use multifactor authentication for
local access to accounts.

    Add or update \"pam_pkcs11.so\" in \"/etc/pam.d/common-auth\" to match the
following line:

    auth [success=2 default=ignore] pam_pkcs11.so
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053',
'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055',
'SRG-OS-000377-GPOS-00162']
  tag gid: 'V-219317'
  tag rid: 'SV-219317r508662_rule'
  tag stig_id: 'UBTU-18-010427'
  tag fix_id: 'F-21041r305280_fix'
  tag cci: ['V-100857', 'SV-109961', 'CCI-001954', 'CCI-000765', 'CCI-000766',
'CCI-000767', 'CCI-000768']
  tag nist: ['IA-2 (12)', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)']

  describe command('grep pam_pkcs11.so /etc/pam.d/common-auth') do
    its('stdout') { should_not be_empty }
  end
end

