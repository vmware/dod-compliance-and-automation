control 'UBTU-22-612035' do
  title 'Ubuntu 22.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).'
  desc 'check', %q(Verify Ubuntu 22.04 LTS, for PKI-based authentication, uses local revocation data when unable to access it from the network by using the following command:

Note: If smart card authentication is not being used on the system, this is not applicable.

     $ grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'
     cert_policy = ca,signature,ocsp_on,crl_auto;

If "cert_policy" is not set to include "crl_auto" or "crl_offline", is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS, for PKI-based authentication, to use local revocation data when unable to access the network to obtain it remotely.

Add or update the "cert_policy" option in "/etc/pam_pkcs11/pam_pkcs11.conf" to include "crl_auto" or "crl_offline".

cert_policy = ca,signature,ocsp_on, crl_auto;

If the system is missing an "/etc/pam_pkcs11/" directory and an "/etc/pam_pkcs11/pam_pkcs11.conf", find an example to copy into place and modify accordingly at "/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz".'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64307r953545_chk'
  tag severity: 'medium'
  tag gid: 'V-260578'
  tag rid: 'SV-260578r1015021_rule'
  tag stig_id: 'UBTU-22-612035'
  tag gtitle: 'SRG-OS-000384-GPOS-00167'
  tag fix_id: 'F-64215r953546_fix'
  tag 'documentable'
  tag cci: ['CCI-001991', 'CCI-004068']
  tag nist: ['IA-5 (2) (d)', 'IA-5 (2) (b) (2)']

  config_file_exists = file('/etc/pam_pkcs11/pam_pkcs11.conf').exist?
  if config_file_exists
    describe.one do
      describe parse_config_file('/etc/pam_pkcs11/pam_pkcs11.conf') do
        its('cert_policy') { should include 'crl_auto' }
      end
      describe parse_config_file('/etc/pam_pkcs11/pam_pkcs11.conf') do
        its('cert_policy') { should include 'crl_offline' }
      end
    end
  else
    describe '/etc/pam_pkcs11/pam_pkcs11.conf exists' do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
