# encoding: UTF-8

control 'V-219316' do
  title "The Ubuntu operating system must map the authenticated identity to the
user or group account for PKI-based authentication."
  desc  "Without mapping the certificate used to authenticate to the user
account, the ability to determine the identity of the individual user or group
will not be available for forensic analysis."
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system has the 'libpam-pkcs11’ package
installed, by running the following command:

    # dpkg -l | grep libpam-pkcs11

    If \"libpam-pkcs11\" is not installed, this is a finding.

    Check if use_mappers is set to pwent in /etc/pam_pkcs11/pam_pkcs11.conf file
    # grep use_mappers /etc/pam_pkcs11/pam_pkcs11.conf
    use_mappers = pwent

    If ‘use_mappers’ is not found or is not set to pwent this is a finding.
  "
  desc  'fix', "
    Install libpam-pkcs11 package on the system.

    Set use_mappers=pwent in /etc/pam_pkcs11/pam_pkcs11.conf

    If the system is missing an \"/etc/pam_pkcs11/\" directory and an
\"/etc/pam_pkcs11/pam_pkcs11.conf\", find an example to copy into place and
modify accordingly at
\"/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz\".
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag gid: 'V-219316'
  tag rid: 'SV-219316r508662_rule'
  tag stig_id: 'UBTU-18-010426'
  tag fix_id: 'F-21040r305277_fix'
  tag cci: ['V-100855', 'SV-109959', 'CCI-000187']
  tag nist: ['IA-5 (2) (c)']

  config_file = '/etc/pam_pkcs11/pam_pkcs11.conf'
  config_file_exists = file(config_file).exist?

  describe package('libpam-pkcs11') do
    it { should be_installed }
  end

  if config_file_exists
    describe parse_config_file(config_file) do
      its('use_mappers') { should cmp 'pwent' }
    end
  else
    describe (config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end

end

