control 'PHTN-30-000055' do
  title 'The Photon operating system must configure auditd to keep five rotated log files.'
  desc  'Audit logs are most useful when accessible by date, rather than size. This can be accomplished through a combination of an audit log rotation cron job, setting a reasonable number of logs to keep and configuring auditd to not rotate the logs on its own. This ensures that audit logs are accessible to the ISSO in the event of a central log processing failure.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep \"^num_logs\" /etc/audit/auditd.conf

    Expected result:

    num_logs = 5

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/auditd.conf

    Add or change the \"num_logs\" line as follows:

    num_logs = 5

    At the command line, execute the following command(s):

    # killproc auditd -TERM
    # systemctl start auditd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000055'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe auditd_conf do
    its('num_logs') { should cmp '5' }
  end
end
