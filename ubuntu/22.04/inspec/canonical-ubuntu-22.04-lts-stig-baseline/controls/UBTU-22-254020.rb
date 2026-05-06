control 'UBTU-22-254020' do
  title 'Ubuntu 22.04 LTS must ensure SSSD performs certificate path validation, including revocation checking, against a trusted anchor for PKI-based authentication.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a certification authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS, for PKI-based authentication, has valid certificates by constructing a certification path to an accepted trust anchor.

Verify the pam service is listed under [sssd] with the following command:

$ sudo grep -A 1 '^\[sssd\]' /etc/sssd/sssd.conf
[sssd]
services = nss,pam,ssh

If "pam" is not listed in services, this is a finding.

Verify the pam service is set to use pam for smart card authentication in the [pam] section of /etc/sssd/sssd.conf with the following command:

$ sudo grep -A 1 '^\[pam]' /etc/sssd/sssd.conf
[pam]
pam_cert_auth = True

If "pam_cert_auth = True" is not returned, this is a finding.

Verify "ca" is enabled in "certificate_verification" with the following command:

$ sudo grep certificate_verification /etc/sssd/sssd.conf
certificate_verification = ca_cert,ocsp

If "certificate_verification" is not set to "ca" or the line is commented out, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS, for PKI-based authentication, to validate certificates by constructing a certification path to an accepted trust anchor.

Add or update the /etc/sssd/sssd.conf so that the following entries are in the correct sections of the file:

$ sudo vi /etc/sssd/sssd.conf

[sssd]
services = nss,pam,ssh
config_file_version = 2

[pam]
pam_cert_auth = True

[domain/example.com]
ldap_user_certificate = usercertificate;binary
certificate_verification = ca_cert,ocsp
ca_cert = /etc/ssl/certs/ca-certificates.crt'
  impact 0.5
  tag check_id: 'C-78968r1107269_chk'
  tag severity: 'medium'
  tag gid: 'V-274867'
  tag rid: 'SV-274867r1107270_rule'
  tag stig_id: 'UBTU-22-254020'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78873r1101741_fix'
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-004909']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-17 b']

  sssd_conf_path = input('sssd_conf_path')
  smartcards_used = input('smartcards_used')

  if smartcards_used
    if file(sssd_conf_path).exist?
      sssd_conf = ini(sssd_conf_path)

      describe sssd_conf do
        its(['sssd', 'services']) { should match(/(^|,)pam(,|$)/) }
        its(['pam', 'pam_cert_auth']) { should cmp 'True' }
      end

      domain_sections = sssd_conf.params.keys.select { |section| section.start_with?('domain/') }

      describe.one do
        domain_sections.each do |section|
          describe "SSSD domain section [#{section}]" do
            subject { sssd_conf[section]['certificate_verification'] }
            it { should match(/(^|,)ca_cert(,|$)/) }
          end
        end
      end
    else
      describe file(sssd_conf_path) do
        it { should exist }
      end
    end
  else
    impact 0.0
    describe 'Smartcards not in use for local login so this rule is N/A.' do
      skip 'Smartcards not in use for local login so this rule is N/A.'
    end
  end
end
