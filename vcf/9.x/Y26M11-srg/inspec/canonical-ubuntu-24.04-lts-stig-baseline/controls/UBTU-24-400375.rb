control 'UBTU-24-400375' do
  title 'Ubuntu 24.04 LTS, for PKI-based authentication, Privileged Access Management (PAM) must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a certification authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.

'
  desc 'check', %q(Verify Ubuntu 24.04 LTS, for PKI-based authentication, has valid certificates by constructing a certification path to an accepted trust anchor.

Determine which pkcs11 module is being used via the "use_pkcs11_module" in "/etc/pam_pkcs11/pam_pkcs11.conf" and then ensure "ca" is enabled in "cert_policy" with the following command:

$ sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca

cert_policy = ca,signature,ocsp_on;

If "cert_policy" is not set to "ca" or the line is commented out, this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS, for PKI-based authentication, to validate certificates by constructing a certification path to an accepted trust anchor.

Determine which pkcs11 module is being used via the "use_pkcs11_module" in "/etc/pam_pkcs11/pam_pkcs11.conf" and ensure "ca" is enabled in "cert_policy".

Add or update the "cert_policy" to ensure "ca" is enabled:

cert_policy = ca,signature,ocsp_on;

If the system is missing an "/etc/pam_pkcs11/" directory and an "/etc/pam_pkcs11/pam_pkcs11.conf", find an example to copy into place and modify accordingly at "https://manpages.ubuntu.com/manpages/xenial/man8/pam_pkcs11.8.html".'
  impact 0.5
  tag check_id: 'C-74770r1066698_chk'
  tag severity: 'medium'
  tag gid: 'V-270737'
  tag rid: 'SV-270737r1067178_rule'
  tag stig_id: 'UBTU-24-400375'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-74671r1067168_fix'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000775-GPOS-00230']
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-004909']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-17 b']

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
          it 'should include ca' do
            expect(line).to match(/\bca\b/)
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
