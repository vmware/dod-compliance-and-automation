# encoding: UTF-8

control 'V-219320' do
  title "The Ubuntu operating system must implement certificate status checking
for multifactor authentication."
  desc  "The use of PIV credentials facilitates standardization and reduces the
risk of unauthorized access.

    DoD has mandated the use of the CAC to support identity management and
personal authentication for systems covered under Homeland Security
Presidential Directive (HSPD) 12, as well as making the CAC a primary component
of layered protection for national security systems.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system implements certificate status checking
for multifactor authentication.

    Check that certificate status checking for multifactor authentication is
implemented with the following command:

    # sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk
'/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep
cert_policy | grep ocsp_on

    cert_policy = ca,signature,ocsp_on;

    If \"cert_policy\" is not set to \"ocsp_on\", or the line is commented out,
this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to certificate status checking for
multifactor authentication.

    Modify all of the cert_policy lines in \"/etc/pam_pkcs11/pam_pkcs11.conf\"
to include ocsp_on.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000377-GPOS-00162'
  tag gid: 'V-219320'
  tag rid: 'SV-219320r508662_rule'
  tag stig_id: 'UBTU-18-010434'
  tag fix_id: 'F-21044r305289_fix'
  tag cci: ['SV-109967', 'V-100863', 'CCI-001954']
  tag nist: ['IA-2 (12)']

  config_file_exists = file('/etc/pam_pkcs11/pam_pkcs11.conf').exist?

  if config_file_exists
    describe parse_config_file('/etc/pam_pkcs11/pam_pkcs11.conf') do
      its('cert_policy') { should include 'ocsp_on' }
    end
  else
    describe '/etc/pam_pkcs11/pam_pkcs11.conf exists' do
      subject { config_file_exists }
      it { should be true }
    end
  end
end

