control "PHTN-10-000013" do
  title "The Photon operating system audit log must log space limit problems to
syslog."
  desc  "It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000046-GPOS-00022"
  tag gid: nil
  tag rid: "PHTN-10-000013"
  tag stig_id: "PHTN-10-000013"
  tag cci: "CCI-000139"
  tag nist: ["AU-5 a", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep \"^space_left_action\" /etc/audit/auditd.conf

Expected result:

space_left_action = SYSLOG

If the output does not match the expected result, this is a finding."
  desc 'fix', "Open /etc/audit/auditd.conf with a text editor and ensure that the
\"space_left_action\" line is uncommented and set to the following:

space_left_action = SYSLOG

At the command line, execute the following command:

# service auditd reload"

  describe auditd_conf do
    its("space_left_action") { should cmp 'SYSLOG'}
  end

end

