control 'CFLM-5X-000025' do
  title 'The SDDC Manager LCM service must protect log information from unauthorized access.'
  desc  "
    If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to his or her advantage.

    Application servers contain admin interfaces that allow reading and manipulation of log records. Therefore, these interfaces should not allow unfettered access to those records. Application servers also write log data to log files which are stored on the OS, so appropriate file permissions must also be used to restrict access.

    Log information includes all information (e.g., log records, log settings, transaction logs, and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized read access.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /var/log/vmware/vcf/lcm/ -xdev -type f -a '(' -perm -o+w -o -not -user vcf_lcm -o -not -group vcf ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod o-w <file>
    # chown vcf_lcm:vcf <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag satisfies: ['SRG-APP-000119-AS-000079', 'SRG-APP-000120-AS-000080', 'SRG-APP-000267-AS-000170']
  tag gid: 'V-CFLM-5X-000025'
  tag rid: 'SV-CFLM-5X-000025'
  tag stig_id: 'CFLM-5X-000025'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9', 'SI-11 b']

  command('find /var/log/vmware/vcf/lcm/ -type f -xdev').stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_writable.by('others') }
      its('owner') { should eq 'vcf_lcm' }
      its('group') { should eq 'vcf' }
    end
  end
end
