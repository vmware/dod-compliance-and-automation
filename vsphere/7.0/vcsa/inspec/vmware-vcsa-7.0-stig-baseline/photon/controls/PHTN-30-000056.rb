# encoding: UTF-8

control 'PHTN-30-000056' do
  title "The Photon operating system must configure auditd to keep logging in
the event max log file size is reached."
  desc  "Audit logs are most useful when accessible by date, rather than size.
This can be acomplished through a combination of an audit log rotation cron
job, setting a reasonable number of logs to keep and configuring auditd to not
rotate the logs on it's own. This ensures that audit logs are accessible to the
ISSO in the event of a central log processing failure."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep \"^max_log_file_action\" /etc/audit/auditd.conf

    Expected result:

    max_log_file_action = IGNORE

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    Open /etc/audit/auditd.conf with a text editor. Add or change the
\"max_log_file_action\" line as follows:

    max_log_file_action = IGNORE

    At the command line, execute the following command:

    # killproc auditd -TERM
    # systemctl start auditd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag stig_id: 'PHTN-30-000056'
  tag cci: 'CCI-001849'
  tag nist: ['AU-4']

  describe auditd_conf do
    its("max_log_file_action") { should cmp 'IGNORE'}
  end

end

