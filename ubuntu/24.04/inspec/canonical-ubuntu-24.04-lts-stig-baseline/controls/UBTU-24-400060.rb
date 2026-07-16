control 'UBTU-24-400060' do
  title 'Ubuntu 24.04 LTS must electronically verify Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DOD has mandated the use of the common access card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', %q(Verify Ubuntu 24.04 LTS electronically verifies PIV credentials via certificate status checking with the following command:

$ sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on

cert_policy = ca,signature,ocsp_on;

If every returned "cert_policy" line is not set to "ocsp_on", or the line is commented out, this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS to do certificate status checking for multifactor authentication.

Modify all of the "cert_policy" lines in "/etc/pam_pkcs11/pam_pkcs11.conf" to include "ocsp_on".'
  impact 0.5
  tag check_id: 'C-74756r1066656_chk'
  tag severity: 'medium'
  tag gid: 'V-270723'
  tag rid: 'SV-270723r1066658_rule'
  tag stig_id: 'UBTU-24-400060'
  tag gtitle: 'SRG-OS-000377-GPOS-00162'
  tag fix_id: 'F-74657r1066657_fix'
  tag 'documentable'
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']

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
          it 'should include ocsp_on' do
            expect(line).to match(/\bocsp_on\b/)
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
