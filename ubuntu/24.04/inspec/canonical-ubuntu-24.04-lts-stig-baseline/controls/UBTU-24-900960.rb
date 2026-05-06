control 'UBTU-24-900960' do
  title 'Ubuntu 24.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify Ubuntu 24.04 LTS notifies the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity with the following command:

Note: If the space_left_action is set to "email", an email package must be available.

$ sudo grep ^space_left_action /etc/audit/auditd.conf
space_left_action email

$ sudo grep ^space_left /etc/audit/auditd.conf
space_left 250000

If the "space_left" parameter is set to "syslog", is missing, set to blanks, or set to a value less than 25 percent of the space free in the allocated audit record storage, this is a finding.

If the "space_left_action" parameter is missing or set to blanks, this is a finding.

If the "space_left_action" is set to "email", check the value of the "action_mail_acct" parameter with the following command:

$ sudo grep ^action_mail_acct /etc/audit/auditd.conf
action_mail_acct root@localhost

The "action_mail_acct" parameter, if missing, defaults to "root". If the "action_mail_acct parameter" is not set to the email address of the SA(s) and/or ISSO, this is a finding.

If the "space_left_action" is set to "exec", the system executes a designated script. If this script informs the SA of the event, this is not a finding.'
  desc 'fix', 'Edit "/etc/audit/auditd.conf" and set the "space_left_action" parameter to "exec" or "email".

If the "space_left_action" parameter is set to "email", set the "action_mail_acct" parameter to an email address for the SA and ISSO.

If the "space_left_action" parameter is set to "exec", ensure the command being executed notifies the SA and ISSO.

Edit "/etc/audit/auditd.conf" and set the "space_left" parameter to be at least 25 percent of the repository maximum audit record storage capacity.'
  impact 0.3
  tag check_id: 'C-74851r1066941_chk'
  tag severity: 'low'
  tag gid: 'V-270818'
  tag rid: 'SV-270818r1066943_rule'
  tag stig_id: 'UBTU-24-900960'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-74752r1066942_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  security_accounts = input('action_mail_acct')

  describe auditd_conf do
    its('space_left') { should cmp >= '25' }
    its('space_left') { should match(/\d{2}/) }
  end

  if auditd_conf.space_left_action == 'email'
    describe auditd_conf.action_mail_acct do
      it { should_not be_nil }
      it { should_not cmp '' }
      it { should cmp security_accounts }
    end
  else
    describe auditd_conf.space_left_action do
      it { should cmp 'email' }
    end
  end
end
