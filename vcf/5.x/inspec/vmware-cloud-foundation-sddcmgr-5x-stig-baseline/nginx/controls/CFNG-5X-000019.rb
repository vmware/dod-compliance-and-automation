control 'CFNG-5X-000019' do
  title 'The SDDC Manager NGINX service must only be accessible by privileged users.'
  desc  "
    Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

    The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # find /var/log/nginx/ -type f -exec stat -c \"%n is owned by %U and group %G permissions are %a\" {} $1\\;

    If any file is not owned by root or group is not vcf or permissions are more permissive than 0640, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands:

    # chown root:vcf <log file>
    # chmod 640 <log file>

    Replace <log file> with the log files found with incorrect permissions or ownership.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: 'V-CFNG-5X-000019'
  tag rid: 'SV-CFNG-5X-000019'
  tag stig_id: 'CFNG-5X-000019'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  logfiles = command('find /var/log/nginx/ -type f').stdout
  if !logfiles.empty?
    logfiles.split.each do |fname|
      describe file(fname) do
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'vcf' }
        it { should_not be_more_permissive_than('0640') }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
end
