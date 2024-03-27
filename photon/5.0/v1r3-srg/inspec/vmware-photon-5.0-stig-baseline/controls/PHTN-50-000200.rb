control 'PHTN-50-000200' do
  title 'The Photon operating system must configure the Secure Shell (SSH) SyslogFacility.'
  desc  "
    Automated monitoring of remote access sessions allows organizations to detect cyber attacks and ensure ongoing compliance with remote access policies by auditing connection activities.

    Shipping SSH authentication events to syslog allows organizations to use their log aggregators to correlate forensic activities among multiple systems.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i SyslogFacility

    Example result:

    syslogfacility AUTHPRIV

    If \"syslogfacility\" is not set to \"AUTH\" or \"AUTHPRIV\", this is a finding.
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
  tag gid: 'V-PHTN-50-000200'
  tag rid: 'SV-PHTN-50-000200'
  tag stig_id: 'PHTN-50-000200'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  sshdcommand = input('sshdcommand')
  describe.one do
    describe command("#{sshdcommand}|&grep -i SyslogFacility") do
      its('stdout.strip') { should cmp 'SyslogFacility AUTHPRIV' }
    end
    describe command("#{sshdcommand}|&grep -i SyslogFacility") do
      its('stdout.strip') { should cmp 'SyslogFacility AUTH' }
    end
  end
end
