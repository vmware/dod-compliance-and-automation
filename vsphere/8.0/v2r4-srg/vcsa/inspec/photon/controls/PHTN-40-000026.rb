control 'PHTN-40-000026' do
  title 'The Photon operating system must protect audit logs from unauthorized access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.
'
  desc 'check', 'At the command line, run the following command to find the current auditd log location:

# grep -iw log_file /etc/audit/auditd.conf

Example result:

log_file = /var/log/audit/audit.log

At the command line, run the following command using the file found in the previous step to verify auditd logs are protected from authorized access:

# stat -c "%n %U:%G %a" /var/log/audit/audit.log

Example result:

/var/log/audit/audit.log root:root 600

If the audit log file does not have permissions set to "0600", this is a finding.
If the audit log file is not owned by root, this is a finding.
If the audit log file is not group owned by root, this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

#  chmod 0600 <audit log file>
#  chown root:root <audit log file>

Replace <audit log file> with the target log file.

Note: If "log_group" is configured in the auditd.conf file and set to something other than "root", the permissions changes will not be persistent.'
  impact 0.5
  tag check_id: 'C-62551r933492_chk'
  tag severity: 'medium'
  tag gid: 'V-258811'
  tag rid: 'SV-258811r958434_rule'
  tag stig_id: 'PHTN-40-000026'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-62460r933493_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  describe file(auditd_conf('/etc/audit/auditd.conf').log_file) do
    its('mode') { should cmp '0600' }
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
  end
end
