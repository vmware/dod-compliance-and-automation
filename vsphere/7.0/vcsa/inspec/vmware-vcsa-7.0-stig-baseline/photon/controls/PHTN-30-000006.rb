control 'PHTN-30-000006' do
  title 'The Photon operating system must have the sshd SyslogFacility set to "authpriv".'
  desc 'Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities.'
  desc 'check', 'At the command line, run the following command:

# sshd -T|&grep -i SyslogFacility

Expected result:

syslogfacility AUTHPRIV

If there is no output or if the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "SyslogFacility" line is uncommented and set to the following:

SyslogFacility AUTHPRIV

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-60158r887121_chk'
  tag severity: 'medium'
  tag gid: 'V-256483'
  tag rid: 'SV-256483r887123_rule'
  tag stig_id: 'PHTN-30-000006'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-60101r887122_fix'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i syslogfacility") do
    its('stdout.strip') { should cmp 'syslogfacility AUTHPRIV' }
  end
end
