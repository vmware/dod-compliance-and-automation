control 'UBTU-24-901380' do
  title 'Ubuntu 24.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, Ubuntu 24.04 LTS must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Verify that the audit log directory has a mode of "0750" or less permissive.

Determine where the audit logs are stored with the following command:

$ sudo grep -iw ^log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, determine if the directory has a mode of "0750" or less with the following command:

$ sudo stat -c "%n %a" /var/log/audit
/var/log/audit 750

If the audit log directory has a mode more permissive than "0750", this is a finding.'
  desc 'fix', 'Configure the audit log directory to have a mode of "0750" or less permissive.

Determine where the audit logs are stored with the following command:

$ sudo grep -iw ^log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, configure the audit log directory to have a mode of "0750" or less permissive by using the following command:

$ sudo chmod -R  750 /var/log/audit'
  impact 0.5
  tag check_id: 'C-74863r1066977_chk'
  tag severity: 'medium'
  tag gid: 'V-270830'
  tag rid: 'SV-270830r1068397_rule'
  tag stig_id: 'UBTU-24-901380'
  tag gtitle: 'SRG-OS-000059-GPOS-00029'
  tag fix_id: 'F-74764r1068396_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']

  log_file = auditd_conf.log_file

  log_file_exists = !log_file.nil?

  if log_file_exists
    log_dir = File.dirname(log_file)
    describe directory(log_dir) do
      its('mode') { should cmp <= '0750' }
    end
  else
    describe("Audit log file #{log_file} exists") do
      subject { log_file_exists }
      it { should be true }
    end
  end
end
