control 'CFSS-5X-000025' do
  title 'The SDDC Manager SOS service must protect log information from unauthorized access.'
  desc  "
    If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to his or her advantage.

    Application servers contain admin interfaces that allow reading and manipulation of log records. Therefore, these interfaces should not allow unfettered access to those records. Application servers also write log data to log files which are stored on the OS, so appropriate file permissions must also be used to restrict access.

    Log information includes all information (e.g., log records, log settings, transaction logs, and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized read access.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # find /var/log/vmware/vcf/sddc-support/*.* -xdev -type f ! -name vcf-sos-gunicorn.log -a '(' -not -perm 640 -o -not -user root -o -not -group vcf ')' -exec ls -ld {} \\;

    # find /var/log/vmware/vcf/sddc-support/sos*/* -xdev -type f -a '(' -not -perm 640 -o -not -user vcf -o -not -group vcf ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.

    Note: Unless a support bundle has been previously generated, the \"/var/log/vmware/vcf/sddc-support/sos*\" location may not exist.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod 640 <file>
    # chown root:vcf <file>

    If files are from a support bundle for example in this path /var/log/vmware/vcf/sddc-support/sos-2020-10-14-13-17-57-2080/* run the following commands:

    # chmod 640 <file>
    # chown vcf:vcf <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag satisfies: ['SRG-APP-000119-AS-000079', 'SRG-APP-000120-AS-000080']
  tag gid: 'V-CFSS-5X-000025'
  tag rid: 'SV-CFSS-5X-000025'
  tag stig_id: 'CFSS-5X-000025'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  logfiles = command('find /var/log/vmware/vcf/sddc-support/*.* -xdev -type f ! -name vcf-sos-gunicorn.log').stdout
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
  logfilessos = command('find /var/log/vmware/vcf/sddc-support/sos*/* -xdev -type f').stdout
  if !logfilessos.empty?
    logfilessos.split.each do |fname|
      describe file(fname) do
        its('owner') { should cmp 'vcf' }
        its('group') { should cmp 'vcf' }
        it { should_not be_more_permissive_than('0640') }
      end
    end
  else
    impact 0.0
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
end
