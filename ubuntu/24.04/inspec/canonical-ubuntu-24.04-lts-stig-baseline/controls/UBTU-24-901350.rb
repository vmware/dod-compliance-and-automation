control 'UBTU-24-901350' do
  title 'Ubuntu 24.04 LTS must permit only authorized groups ownership of the audit log files.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Verify the group owner is set to own newly created audit logs in the audit configuration file with the following command:

$ sudo grep -iw log_group /etc/audit/auditd.conf
log_group = root

If the value of the "log_group" parameter is other than "root", this is a finding.

Determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, determine if the audit log files are owned by the "root" group with the following command:

$ sudo stat -c "%n %G" /var/log/audit/*
/var/log/audit/audit.log root

If the audit log files are owned by a group other than "root", this is a finding.'
  desc 'fix', %q(Configure the audit log directory and its underlying files to be owned by "root" group.

Set the "log_group" parameter of the audit configuration file to the "root" value so when a new log file is created, its group owner is properly set:

$ sudo sed -i '/^log_group/D' /etc/audit/auditd.conf
$ sudo sed -i /^log_file/a'log_group = root' /etc/audit/auditd.conf

Signal the audit daemon to reload the configuration file to update the group owners of existing files:

$ sudo systemctl kill auditd -s SIGHUP)
  impact 0.5
  tag check_id: 'C-74862r1066974_chk'
  tag severity: 'medium'
  tag gid: 'V-270829'
  tag rid: 'SV-270829r1066976_rule'
  tag stig_id: 'UBTU-24-901350'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-74763r1066975_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  log_file = auditd_conf.log_file

  log_file_exists = !log_file.nil?
  if log_file_exists
    describe file(log_file) do
      its('group') { should cmp 'root' }
    end
  else
    describe("Audit log file #{log_file} exists") do
      subject { log_file_exists }
      it { should be true }
    end
  end
end
