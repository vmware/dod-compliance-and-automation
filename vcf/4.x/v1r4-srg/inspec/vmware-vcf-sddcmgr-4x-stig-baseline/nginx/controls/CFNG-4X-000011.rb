control 'CFNG-4X-000011' do
  title 'The SDDC Manager NGINX service log files must only be accessible by privileged users.'
  desc  'The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # find /var/log/nginx/* -type f -exec stat -c \"%n is owned by %U and group %G permissions are %a\" {} $1\\;

    If any file is not owned by root or group is not vcf or permissions are more permissive than \"0640\", this is a finding.
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
  tag gid: 'V-CFNG-4X-000011'
  tag rid: 'SV-CFNG-4X-000011'
  tag stig_id: 'CFNG-4X-000011'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  logfiles = command('find /var/log/nginx/* -maxdepth 1 -type f').stdout
  if !logfiles.empty?
    logfiles.split.each do |fname|
      describe file(fname) do
        its('group') { should cmp 'vcf' }
        its('owner') { should cmp 'root' }
        it { should_not be_more_permissive_than('0640') }
      end
    end
  else
    describe 'No log files found...skipping...' do
      skip 'No log files found...skipping...'
    end
  end
end
