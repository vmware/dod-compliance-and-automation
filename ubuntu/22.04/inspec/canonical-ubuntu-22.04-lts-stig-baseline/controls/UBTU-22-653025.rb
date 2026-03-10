control 'UBTU-22-653025' do
  title 'Ubuntu 22.04 LTS must alert the information system security officer (ISSO) and system administrator (SA) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Verify that the SA and ISSO are notified in the event of an audit processing failure by using the following command:

Note: An email package must be installed on the system for email notifications to be sent.

     $ sudo grep -i action_mail_acct /etc/audit/auditd.conf
     action_mail_acct = <administrator_email_account>

If "action_mail_acct" is not set to the email address of the SA and/or ISSO, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure "auditd" service to notify the SA and ISSO in the event of an audit processing failure.

Add or modify the following line in the "/etc/audit/auditd.conf " file:

action_mail_acct = <administrator_email_account>

Note: Change "administrator_email_account" to the email address of the SA and/or ISSO.

Restart the "auditd" service for the changes take effect:

     $ sudo systemctl restart auditd.service'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64322r953590_chk'
  tag severity: 'low'
  tag gid: 'V-260593'
  tag rid: 'SV-260593r958424_rule'
  tag stig_id: 'UBTU-22-653025'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-64230r953591_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']

  action_mail_acct = auditd_conf.action_mail_acct
  security_accounts = input('action_mail_acct')

  describe 'System Administrator (SA) and Information System Security Officer (ISSO) are notified in the event of an audit processing failure' do
    subject { security_accounts }
    it { should cmp action_mail_acct }
  end
end
