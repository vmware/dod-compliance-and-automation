control 'UBTU-22-653045' do
  title 'Ubuntu 22.04 LTS must be configured so that audit log files are not read- or write-accessible by unauthorized users.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Verify that the audit log files have a mode of "600" or less permissive.

Determine where the audit logs are stored by using the following command:

     $ sudo grep -iw log_file /etc/audit/auditd.conf
     log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, determine if the audit log files have a mode of "600" or less by using the following command:

     $ sudo stat -c "%n %a" /var/log/audit/*
     /var/log/audit/audit.log 600

If the audit log files have a mode more permissive than "600", this is a finding.'
  desc 'fix', 'Configure the audit log files to have a mode of "600" or less permissive.

Using the path of the directory containing the audit logs, configure the audit log files to have a mode of "600" or less permissive by using the following command:

     $ sudo chmod 600 /var/log/audit/*'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64326r953602_chk'
  tag severity: 'medium'
  tag gid: 'V-260597'
  tag rid: 'SV-260597r958434_rule'
  tag stig_id: 'UBTU-22-653045'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-64234r953603_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163']
  tag nist: ['AU-9 a', 'AU-9 a']

  log_file = auditd_conf.log_file

  log_file_exists = !log_file.nil?
  if log_file_exists
    describe file(log_file) do
      it { should_not be_more_permissive_than('0600') }
    end
  else
    describe("Audit log file #{log_file} exists") do
      subject { log_file_exists }
      it { should be true }
    end
  end
end
