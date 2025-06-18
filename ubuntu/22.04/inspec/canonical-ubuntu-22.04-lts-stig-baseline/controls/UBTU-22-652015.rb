control 'UBTU-22-652015' do
  title 'Ubuntu 22.04 LTS must monitor remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyberattacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Verify that Ubuntu 22.04 LTS monitors all remote access methods by using the following command:

     $  grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*
     /etc/rsyslog.d/50-default.conf:auth.*,authpriv.* /var/log/secure
     /etc/rsyslog.d/50-default.conf:daemon.* /var/log/messages

If "auth.*", "authpriv.*", or "daemon.*" are not configured to be logged in at least one of the config files, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to monitor all remote access methods.

Add or modify the following line in the "/etc/rsyslog.d/50-default.conf" file:

auth.*,authpriv.* /var/log/secure
daemon.* /var/log/messages

Restart "rsyslog.service" for the changes to take effect by using the following command:

     $ sudo systemctl restart rsyslog.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64318r953578_chk'
  tag severity: 'medium'
  tag gid: 'V-260589'
  tag rid: 'SV-260589r958406_rule'
  tag stig_id: 'UBTU-22-652015'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-64226r953579_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  describe command('grep -E -r \'^(auth,authpriv\.\*|daemon\.\*)\' /etc/rsyslog.*') do
    its('stdout.strip') { should match(/auth,authpriv\.\*/).or match(/daemon\.\*/) }
  end
end
