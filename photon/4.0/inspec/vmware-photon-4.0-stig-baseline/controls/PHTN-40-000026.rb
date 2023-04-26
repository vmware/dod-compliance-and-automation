control 'PHTN-40-000026' do
  title 'The Photon operating system must protect audit logs from unauthorized read access.'
  desc  "
    Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to find the current auditd log location:

    # grep -iw log_file /etc/audit/auditd.conf

    At the command line, run the following command using the directory found in the previous step to verify auditd are protected from authorized access:

    # stat -c \"%n %U:%G %a\" /var/log/audit/*

    If any log files have permissions not \"0600\", this is a finding.
    If any log files are not owned by root, this is a finding.
    If any log files are not group owned by root, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands:

    #  chmod 0600 <audit log file>
    #  chown root:root <audit log file>

    Replace <audit log file> with the target log file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag gid: 'V-PHTN-40-000026'
  tag rid: 'SV-PHTN-40-000026'
  tag stig_id: 'PHTN-40-000026'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  log_file = auditd_conf('/etc/audit/auditd.conf').log_file.scan(%r{^.*/})[0]
  command("find #{log_file}* -maxdepth 1 -type f").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
    end
  end
end
