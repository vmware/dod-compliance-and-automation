control 'CFDM-4X-000005' do
  title 'The SDDC Manager Domain Manager service log files must only be accessible by privileged users.'
  desc  'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /var/log/vmware/vcf/domainmanager/ -xdev -type f -a '(' -not -perm 640 -o -not -user vcf_domainmanager -o -not -group vcf ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod 640 <file>
    # chown vcf_domainmanager:vcf <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFDM-4X-000005'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9', 'AU-9', 'AU-9']

  command('find /var/log/vmware/vcf/domainmanager/ -xdev -type f').stdout.split.each do |fname|
    describe file(fname) do
      its('group') { should cmp 'vcf' }
      its('owner') { should cmp 'vcf_domainmanager' }
      it { should_not be_more_permissive_than('0640') }
    end
  end
end
