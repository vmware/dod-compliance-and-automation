control 'UBTU-22-612025' do
  title 'Ubuntu 22.04 LTS must electronically verify personal identity verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DOD has mandated the use of the common access card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS electronically verifies PIV credentials via certificate status checking by using the following command:

     $ sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | sudo awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on
     cert_policy = ca,signature,ocsp_on;

If every returned "cert_policy" line is not set to "ocsp_on", the line is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to do certificate status checking for multifactor authentication.

Add or modify all "cert_policy" lines in the "/etc/pam_pkcs11/pam_pkcs11.conf" file with the following:

ocsp_on'
  impact 0.5
  tag check_id: 'C-64305r1069113_chk'
  tag severity: 'medium'
  tag gid: 'V-260576'
  tag rid: 'SV-260576r1069114_rule'
  tag stig_id: 'UBTU-22-612025'
  tag gtitle: 'SRG-OS-000377-GPOS-00162'
  tag fix_id: 'F-64213r953540_fix'
  tag 'documentable'
  tag cci: ['CCI-001954']
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
