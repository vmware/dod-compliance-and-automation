control 'PHTN-50-000021' do
  title 'The Photon operating system must alert the ISSO and SA in the event of an audit processing failure.'
  desc  "
    It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify auditd is configured to send an alert via syslog in the event of an audit processing failure:

    # grep -E \"^disk_full_action|^disk_error_action|^admin_space_left_action\" /etc/audit/auditd.conf

    Example result:

    admin_space_left_action = SYSLOG
    disk_full_action = SYSLOG
    disk_error_action = SYSLOG

    If \"disk_full_action\", \"disk_error_action\", and \"admin_space_left_action\" are not set to SYSLOG or are missing, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/auditd.conf

    Ensure the following lines are present, not duplicated, and not commented:

    disk_full_action = SYSLOG
    disk_error_action = SYSLOG
    admin_space_left_action = SYSLOG

    At the command line, run the following command:

    # pkill -SIGHUP auditd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag satisfies: ['SRG-OS-000344-GPOS-00135']
  tag gid: 'V-PHTN-50-000021'
  tag rid: 'SV-PHTN-50-000021'
  tag stig_id: 'PHTN-50-000021'
  tag cci: ['CCI-000139', 'CCI-001858']
  tag nist: ['AU-5 (2)', 'AU-5 a']

  describe auditd_conf do
    its('disk_full_action') { should cmp 'SYSLOG' }
    its('disk_error_action') { should cmp 'SYSLOG' }
    its('admin_space_left_action') { should cmp 'SYSLOG' }
  end
end
