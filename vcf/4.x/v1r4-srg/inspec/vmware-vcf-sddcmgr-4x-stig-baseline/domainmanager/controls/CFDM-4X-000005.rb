control 'CFDM-4X-000005' do
  title 'The SDDC Manager Domain Manager service log files must only be accessible by privileged users.'
  desc  'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /var/log/vmware/vcf/domainmanager/ -xdev ! -name domainmanager.out -type f -a '(' -perm -o+w -o -not -user vcf_domainmanager -o -not -group vcf ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod o-w <file>
    # chown vcf_domainmanager:vcf <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: 'V-CFDM-4X-000005'
  tag rid: 'SV-CFDM-4X-000005'
  tag stig_id: 'CFDM-4X-000005'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  logfiles = command('find /var/log/vmware/vcf/domainmanager/ -xdev -type f ! -name domainmanager.out').stdout
  if !logfiles.empty?
    logfiles.split.each do |fname|
      describe file(fname) do
        it { should_not be_writable.by('others') }
        its('group') { should cmp 'vcf' }
        its('owner') { should cmp 'vcf_domainmanager' }
      end
    end
  else
    describe 'No log files found...skipping...' do
      skip 'No log files found...skipping...'
    end
  end
end
