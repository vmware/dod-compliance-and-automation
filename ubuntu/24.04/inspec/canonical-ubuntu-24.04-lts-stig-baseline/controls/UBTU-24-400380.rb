control 'UBTU-24-400380' do
  title 'Ubuntu 24.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).'
  desc 'check', %q(Note: If smart card authentication is not being used on the system, this is not applicable.

Verify Ubuntu 24.04 LTS, for PKI-based authentication, uses local revocation data when unable to access it from the network with the following command:

$ grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'
cert_policy = ca,signature,ocsp_on,crl_auto;

If "cert_policy" is not set to include "crl_auto" or "crl_offline", this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS, for PKI-based authentication, to use local revocation data when unable to access the network to obtain it remotely.

Add or update the "cert_policy" option in "/etc/pam_pkcs11/pam_pkcs11.conf" to include "crl_auto" or "crl_offline".

cert_policy = ca,signature,ocsp_on, crl_auto;

If the system is missing an "/etc/pam_pkcs11/" directory and an "/etc/pam_pkcs11/pam_pkcs11.conf", find an example to copy into place and modify accordingly at "/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz".'
  impact 0.5
  tag check_id: 'C-74771r1066701_chk'
  tag severity: 'medium'
  tag gid: 'V-270738'
  tag rid: 'SV-270738r1066703_rule'
  tag stig_id: 'UBTU-24-400380'
  tag gtitle: 'SRG-OS-000384-GPOS-00167'
  tag fix_id: 'F-74672r1066702_fix'
  tag 'documentable'
  tag cci: ['CCI-004068']
  tag nist: ['IA-5 (2) (b) (2)']

  pam_pkcs11_config_file = input('pam_pkcs11_config_file')
  config_file_exists = file(pam_pkcs11_config_file).exist?

  libpam_pkcs11_package = package('libpam-pkcs11')

  if libpam_pkcs11_package.installed?
    if config_file_exists

      cert_policy_lines = file(pam_pkcs11_config_file).content.lines.select do |line|
        line =~ /^\s*cert_policy\s*=/ && !line.strip.start_with?('#')
      end

      cert_policy_lines.each do |line|
        describe "cert_policy line: #{line.strip}" do
          it 'should include crl_auto or crl_offline' do
            expect(line).to match(/\b(crl_auto|crl_offline)\b/)
          end
        end
      end

    else
      describe pam_pkcs11_config_file do
        subject { config_file_exists }
        it { should be true }
      end
    end
  else
    impact 0.0
    describe 'Smartcards not in use for local login so this rule is N/A.' do
      skip 'Smartcards not in use for local login so this rule is N/A.'
    end
  end
end
