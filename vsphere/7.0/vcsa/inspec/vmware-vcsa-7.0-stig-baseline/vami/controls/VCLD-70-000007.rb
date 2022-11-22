control 'VCLD-70-000007' do
  title 'VAMI log files must only be accessible by privileged users.'
  desc  "
    Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve.

    In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c \"%n has %a permissions and is owned by %U:%G\" /opt/vmware/var/log/lighttpd/*.log

    Expected result:

    /opt/vmware/var/log/lighttpd/access.log has 644 permissions and is owned by root:root
    /opt/vmware/var/log/lighttpd/error.log has 644 permissions and is owned by root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # chown root:root /opt/vmware/var/log/lighttpd/*.log
    # chmod 644 /opt/vmware/var/log/lighttpd/*.log
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000007'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_more_permissive_than('0644') }
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
    end
  end
end
