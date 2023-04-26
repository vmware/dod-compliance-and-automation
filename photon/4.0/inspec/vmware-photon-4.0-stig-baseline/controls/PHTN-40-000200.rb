control 'PHTN-40-000200' do
  title 'The Photon operating system must configure the sshd SyslogFacility.'
  desc  "
    Automated monitoring of remote access sessions allows organizations to detect cyber attacks and ensure ongoing compliance with remote access policies by auditing connection activities.

    Shipping sshd authentication events to syslog allows organizations to use their log aggregators to correlate forensic activities among multiple systems.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i SyslogFacility

    Expected result:

    syslogfacility AUTHPRIV

    If there is no output or if the output does not match expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"SyslogFacility\" line is uncommented and set to the following:

    SyslogFacility AUTHPRIV

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-PHTN-40-000200'
  tag rid: 'SV-PHTN-40-000200'
  tag stig_id: 'PHTN-40-000200'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i SyslogFacility") do
    its('stdout.strip') { should cmp 'SyslogFacility AUTHPRIV' }
  end
end
