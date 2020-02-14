control "PHTN-10-000014" do
  title "The Photon operating system audit log must attempt to log audit
failures to syslog."
  desc  "It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000047-GPOS-00023"
  tag gid: nil
  tag rid: "PHTN-10-000014"
  tag stig_id: "PHTN-10-000014"
  tag cci: "CCI-000140"
  tag nist: ["AU-5 b", "Rev_4"]
  desc 'check', "At the command line, execute the following commands:

# grep -E \"^disk_full_action|^disk_error_action|^admin_space_left_action\"
/etc/audit/auditd.conf

If any of the above parameters are not set to SYSLOG or are missing, this is a
finding."
  desc 'fix', "Open /etc/audit/auditd.conf with a text editor and ensure that the
following lines are present, not duplicated and not commented:

disk_full_action = SYSLOG
disk_error_action = SYSLOG
admin_space_left_action = SYSLOG

At the command line, execute the following command:

# service auditd reload"

  describe auditd_conf do
    its("disk_full_action") { should cmp 'SYSLOG'}
    its("disk_error_action") { should cmp 'SYSLOG'}
    its("admin_space_left_action") { should cmp 'SYSLOG'}
  end

end

