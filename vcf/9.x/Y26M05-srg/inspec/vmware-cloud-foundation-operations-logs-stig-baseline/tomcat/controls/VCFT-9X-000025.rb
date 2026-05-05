control 'VCFT-9X-000025' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must protect log information from unauthorized access.'
  desc  "
    If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to his or her advantage.

    Application servers contain admin interfaces that allow reading and manipulation of log records. Therefore, these interfaces should not allow unfettered access to those records. Application servers also write log data to log files which are stored on the OS, so appropriate file permissions must also be used to restrict access.

    Log information includes all information (e.g., log records, log settings, transaction logs, and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized read access.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # find /var/log/loginsight/apache-tomcat/logs /usr/lib/loginsight/application/3rd_party/apache-tomcat/logs -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # chmod o-w <file>
    # chown root:root <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag satisfies: ['SRG-APP-000119-AS-000079', 'SRG-APP-000120-AS-000080']
  tag gid: 'V-VCFT-9X-000025'
  tag rid: 'SV-VCFT-9X-000025'
  tag stig_id: 'VCFT-9X-000025'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a']

  command("find '#{input('logPath')}' '#{input('accesslogPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_writable.by('others') }
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
    end
  end
end
