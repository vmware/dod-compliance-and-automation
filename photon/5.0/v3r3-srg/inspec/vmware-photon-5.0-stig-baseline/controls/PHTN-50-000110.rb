control 'PHTN-50-000110' do
  title 'The Photon operating system must allocate audit record storage capacity to store audit records when audit records are not immediately sent to a central audit record storage facility.'
  desc  'Audit logs are most useful when accessible by date, rather than size. This can be accomplished through a combination of an audit log rotation and setting a reasonable number of logs to keep. This ensures that audit logs are accessible to the ISSO in the event of a central log processing failure.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify auditd is configured to keep a number of audit logs in the event of a central log processing failure:

    # grep -E \"^num_logs|^max_log_file_action\" /etc/audit/auditd.conf

    Example result:

    num_logs = 5
    max_log_file_action = ROTATE

    If \"num_logs\" is not configured to \"5\" or greater, this is a finding.
    If \"max_log_file_action\" is not configured to \"ROTATE\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/auditd.conf

    Ensure the following lines are present, not duplicated, and not commented:

    num_logs = 5
    max_log_file_action = ROTATE

    At the command line, run the following command:

    # pkill -SIGHUP auditd
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-PHTN-50-000110'
  tag rid: 'SV-PHTN-50-000110'
  tag stig_id: 'PHTN-50-000110'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe auditd_conf do
    its('num_logs') { should cmp >= '5' }
    its('max_log_file_action') { should cmp 'ROTATE' }
  end
end
