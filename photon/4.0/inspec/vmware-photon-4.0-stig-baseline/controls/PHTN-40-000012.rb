control 'PHTN-40-000012' do
  title 'The Photon operating system must monitor remote access logins.'
  desc  "
    Automated monitoring of remote access sessions allows organizations to detect cyber attacks and ensure ongoing compliance with remote access policies by auditing connection activities.

    Shipping sshd authentication events to syslog allows organizations to use their log aggregators to correlate forensic activities among multiple systems.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify rsyslog is configured to log authentication requests for ssh:

    # grep \"^authpriv\" /etc/rsyslog.conf

    Example result:

    authpriv.*   /var/log/auth.log

    If \"authpriv.*\" is not configured, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/rsyslog.conf

    Add or update the following line:

    authpriv.*   /var/log/auth.log

    Note: The path can be substituted for another suitable log destination dedicated to authentication logs.

    At the command line, run the following command:

    # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-PHTN-40-000012'
  tag rid: 'SV-PHTN-40-000012'
  tag stig_id: 'PHTN-40-000012'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  describe command('grep "^authpriv" /etc/rsyslog.conf') do
    its('stdout.strip') { should match /authpriv\.\*[\s]*#{input('authprivlog')}/ }
  end
end
