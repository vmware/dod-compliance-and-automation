control 'VRPE-8X-000005' do
  title 'The VMware Aria Operations Apache server log files must only be accessible by privileged users.'
  desc  "
    Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

    The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # stat -c %a:%U:%G /var/log/apache2/access_log

    Expected result:

    640:root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod 640 /var/log/apache2/access_log
    # chown root:root /var/log/apache2/access_log

    Navigate to and open:

    /etc/login.defs

    Navigate to the umask setting.

    Change the umask setting to \"077\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: 'V-VRPE-8X-000005'
  tag rid: 'SV-VRPE-8X-000005'
  tag stig_id: 'VRPE-8X-000005'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  describe file(input('accessLogFile')) do
    it { should_not be_more_permissive_than('0640') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end

  # Filter out commented line
  describe command('grep UMASK /etc/login.defs | grep -v "^#"') do
    its('stdout.strip') { should cmp 'UMASK 077' }
  end
end
