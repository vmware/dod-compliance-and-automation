control 'PHTN-30-000006' do
  title 'The Photon operating system must have the sshd SyslogFacility set to "authpriv".'
  desc  'Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # sshd -T -f /etc/ssh/sshd_config_effective |&grep -i SyslogFacility

    Expected result:

    syslogfacility AUTHPRIV

    If there is no output or if the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config_effective

    Ensure the \"SyslogFacility\" line is uncommented and set to the following:

    SyslogFacility AUTHPRIV

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-PHTN-30-000006'
  tag rid: 'SV-PHTN-30-000006'
  tag stig_id: 'PHTN-30-000006'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i syslogfacility") do
    its('stdout.strip') { should cmp 'syslogfacility AUTHPRIV' }
  end
end
