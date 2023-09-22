control 'VCRP-80-000019' do
  title 'The vCenter Envoy and Rhttpproxy service log files permissions must be set correctly.'
  desc  "
    Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, usernames, etc.

    The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by nonprivileged users.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # find /var/log/vmware/rhttpproxy/ -xdev -type f -a '(' -perm -o+w -o -not -user rhttpproxy -o -not -group rhttpproxy ')' -exec ls -ld {} \\;
    # find /var/log/vmware/envoy/ -xdev -type f -a '(' -perm -o+w -o -not -user envoy -o -not -group envoy ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands for rhttpproxy log files:

    # chmod o-w <file>
    # chown rhttpproxy:rhttpproxy <file>

    or

    At the command prompt, run the following commands for envoy log files:

    # chmod o-w <file>
    # chown envoy:envoy <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: 'V-VCRP-80-000019'
  tag rid: 'SV-VCRP-80-000019'
  tag stig_id: 'VCRP-80-000019'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  logfiles = command('find /var/log/vmware/rhttpproxy/ -type f -xdev').stdout
  if !logfiles.empty?
    logfiles.split.each do |fname|
      describe file(fname) do
        it { should_not be_writable.by('others') }
        its('owner') { should eq 'rhttpproxy' }
        its('group') { should eq 'rhttpproxy' }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
  logfilesenvoy = command('find /var/log/vmware/envoy/ -type f -xdev').stdout
  if !logfilesenvoy.empty?
    logfilesenvoy.split.each do |fname|
      describe file(fname) do
        it { should_not be_writable.by('others') }
        its('owner') { should eq 'envoy' }
        its('group') { should eq 'envoy' }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
end
