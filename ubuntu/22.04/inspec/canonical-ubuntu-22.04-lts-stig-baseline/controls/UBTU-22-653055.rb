control 'UBTU-22-653055' do
  title 'Ubuntu 22.04 LTS must permit only authorized groups ownership of the audit log files.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Verify the group owner of newly created audit logs is "root" by using the following command:

     $ sudo grep -iw log_group /etc/audit/auditd.conf
     log_group = root

If "log_group" is not set to "root", this is a finding.'
  desc 'fix', 'Configure the group owner of newly created audit logs to be "root".

Add or modify the following lines in the "/etc/audit/auditd.conf " file:

log_group = root

Reload the configuration file of the audit service to update the group ownership of existing files:

     $ sudo systemctl kill auditd -s SIGHUP'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64328r953608_chk'
  tag severity: 'medium'
  tag gid: 'V-260599'
  tag rid: 'SV-260599r958434_rule'
  tag stig_id: 'UBTU-22-653055'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-64236r953609_fix'
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
