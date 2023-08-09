control 'PHTN-30-000007' do
  title 'The Photon operating system must have sshd authentication logging enabled.'
  desc 'Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities.

Shipping sshd authentication events to syslog allows organizations to use their log aggregators to correlate forensic activities among multiple systems.'
  desc 'check', 'At the command line, run the following command:

# grep "^authpriv" /etc/rsyslog.conf

Expected result should be similar to the following:

authpriv.*   /var/log/auth.log

If "authpriv" is not configured to be logged, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/rsyslog.conf

Add the following line:

authpriv.*   /var/log/auth.log

Note: The path can be substituted for another suitable log destination.

At the command line, run the following command:

# systemctl restart rsyslog.service'
  impact 0.5
  tag check_id: 'C-60159r887124_chk'
  tag severity: 'medium'
  tag gid: 'V-256484'
  tag rid: 'SV-256484r887126_rule'
  tag stig_id: 'PHTN-30-000007'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-60102r887125_fix'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  describe command('grep "^authpriv" /etc/rsyslog.conf') do
    its('stdout.strip') { should match /authpriv\.\*.*#{input('authprivlog')}/ }
  end
end
