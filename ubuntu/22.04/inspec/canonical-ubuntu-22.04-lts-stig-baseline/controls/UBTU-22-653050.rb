control 'UBTU-22-653050' do
  title 'Ubuntu 22.04 LTS must be configured to permit only authorized users ownership of the audit log files.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Verify the audit log files are owned by "root" account.

Determine where the audit logs are stored by using the following command:

     $ sudo grep -iw log_file /etc/audit/auditd.conf
     log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, determine if the audit log files are owned by the "root" user by using the following command:

     $ sudo stat -c "%n %U" /var/log/audit/*
     /var/log/audit/audit.log root

If the audit log files are owned by a user other than "root", this is a finding.'
  desc 'fix', 'Configure the audit log directory and its underlying files to be owned by "root" user.

Using the path of the directory containing the audit logs, configure the audit log files to be owned by "root" user by using the following command:

     $ sudo chown root /var/log/audit/*'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64327r953605_chk'
  tag severity: 'medium'
  tag gid: 'V-260598'
  tag rid: 'SV-260598r958434_rule'
  tag stig_id: 'UBTU-22-653050'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-64235r953606_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  log_file = auditd_conf.log_file

  log_file_exists = !log_file.nil?
  if log_file_exists
    describe file(log_file) do
      its('owner') { should cmp 'root' }
    end
  else
    describe("Audit log file #{log_file} exists") do
      subject { log_file_exists }
      it { should be true }
    end
  end
end
