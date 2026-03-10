control 'UBTU-22-612040' do
  title 'Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify that "use_mappers" is set to "pwent" in "/etc/pam_pkcs11/pam_pkcs11.conf" file by using the following command:

     $ grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf
     use_mappers = pwent

If "use_mappers" does not contain "pwent", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Set "use_mappers=pwent" in "/etc/pam_pkcs11/pam_pkcs11.conf" or, if there is already a comma-separated list of mappers, add it to the list, separated by comma, and before the null mapper.

If the system is missing an "/etc/pam_pkcs11/" directory and an "/etc/pam_pkcs11/pam_pkcs11.conf", find an example to copy into place and modify accordingly at "/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz".'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64308r953548_chk'
  tag severity: 'high'
  tag gid: 'V-260579'
  tag rid: 'SV-260579r958452_rule'
  tag stig_id: 'UBTU-22-612040'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-64216r953549_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']

  config_file_exists = file('/etc/pam_pkcs11/pam_pkcs11.conf').exist?

  if config_file_exists
    describe parse_config_file('/etc/pam_pkcs11/pam_pkcs11.conf') do
      its('use_mappers') { should cmp 'pwent' }
    end
  else
    describe '/etc/pam_pkcs11/pam_pkcs11.conf exists' do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
