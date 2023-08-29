control 'WOAT-3X-000021' do
  title 'Workspace ONE Access log files must only be accessible by privileged users.'
  desc  'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc. The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /opt/vmware/horizon/workspace/logs/ -xdev -type f -a '(' -perm -o+r -o -not -user horizon -o -not -group www ')' -exec ls -ld {} \\;

    If any catalina.log and localhost_access_log* log files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # chmod 640 <file>
    # chown horizon:www <file>

    Note: Subsitute <file> with the listed file
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: 'V-WOAT-3X-000021'
  tag rid: 'SV-WOAT-3X-000021'
  tag stig_id: 'WOAT-3X-000021'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']
  tag mitigations: 'syslog'

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_more_permissive_than('0640') }
      its('owner') { should eq 'horizon' }
      its('group') { should eq 'www' }
    end
  end
end
