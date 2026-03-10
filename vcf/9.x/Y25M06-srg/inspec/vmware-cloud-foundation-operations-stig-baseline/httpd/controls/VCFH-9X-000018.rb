control 'VCFH-9X-000018' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service log files must only be accessible by privileged users.'
  desc  "
    Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

    The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify log permissions are configured appropriately.

    At the command line, run the following:

    # find /var/log/apache2/access_log -type f -exec stat -c \"%n is owned by %U and group %G permissions are %a\" {} $1\\;

    If any log file is not owned by root or an authorized user, this is a finding.

    If any log file is not group owned by root or an authorized user, this is a finding.

    If any log file is more permissive than 0640, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following:

    # chown root:root <log file>
    # chmod 640 <log file>

    Replace <log file> with the log files found with incorrect permissions or ownership and update user and group as appropriate.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: 'V-VCFH-9X-000018'
  tag rid: 'SV-VCFH-9X-000018'
  tag stig_id: 'VCFH-9X-000018'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a']

  apache_log_dir = input('apache_log_dir')

  badfiles = command("find #{apache_log_dir} -type f -a '(' -perm -o+r -o -not -user root -o -not -group root ')'").stdout
  badfilesstderr = command("find #{apache_log_dir} -type f -a '(' -perm -o+r -o -not -user root -o -not -group root ')'").stderr

  if !badfiles.empty?
    badfiles.split.each do |badfile|
      describe file(badfile) do
        it { should_not be_more_permissive_than('0640') }
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
      end
    end
  else
    describe "Files found with incorrect permissions under #{apache_log_dir}" do
      subject { badfiles }
      it { should be_empty }
    end
    describe 'Find command should not have errors' do
      subject { badfilesstderr }
      it { should cmp '' }
    end
  end
end
