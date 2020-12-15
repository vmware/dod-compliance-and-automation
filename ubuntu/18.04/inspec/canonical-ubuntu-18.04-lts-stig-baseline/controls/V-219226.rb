# encoding: UTF-8

control 'V-219226' do
  title "The Ubuntu operating system must alert the ISSO and SA (at a minimum)
in the event of an audit processing failure."
  desc  "It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the
audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

    This requirement applies to each audit data storage repository (i.e.,
distinct information system component where audit records are stored), the
centralized audit storage capacity of organizations (i.e., all audit data
storage repositories combined), or both.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the System Administrator (SA) and Information System Security
Officer (ISSO) (at a minimum) are notified in the event of an audit processing
failure.

    Check that the Ubuntu operating system notifies the SA and ISSO (at a
minimum) win the event of an audit processing failure with the following
command:

    # sudo grep action_mail_acct = root /etc/audit/auditd.conf

    action_mail_acct = root

    If the value of the \"action_mail_acct\" keyword is not set to \"root\"
and/or other accounts for security personnel, the \"action_mail_acct\" keyword
is missing, or the returned line is commented out, this is a finding.
  "
  desc  'fix', "
    Configure \"auditd\" service to notify the System Administrator (SA) and
Information System Security Officer (ISSO) in the event of an audit processing
failure.

    Edit the following line in \"/etc/audit/auditd.conf\" to ensure that
administrators are notified via email for those situations:

    action_mail_acct = root

    Restart the auditd service so the changes take effect:
    # sudo systemctl restart auditd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag gid: 'V-219226'
  tag rid: 'SV-219226r508662_rule'
  tag stig_id: 'UBTU-18-010300'
  tag fix_id: 'F-20950r305007_fix'
  tag cci: ['SV-109783', 'V-100679', 'CCI-000139']
  tag nist: ['AU-5 a']

  action_mail_acct = auditd_conf.action_mail_acct
  security_accounts = input('action_mail_acct')

  describe 'System Administrator (SA) and Information System Security Officer (ISSO) are notified in the event of an audit processing failure' do
    subject { security_accounts }
    it { should cmp action_mail_acct }
  end
end

