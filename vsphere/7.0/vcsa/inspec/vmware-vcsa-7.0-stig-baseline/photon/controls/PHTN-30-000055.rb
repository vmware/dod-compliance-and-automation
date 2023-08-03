control 'PHTN-30-000055' do
  title 'The Photon operating system must configure auditd to keep five rotated log files.'
  desc 'Audit logs are most useful when accessible by date, rather than size. This can be accomplished through a combination of an audit log rotation cron job, setting a reasonable number of logs to keep, and configuring auditd to not rotate the logs on its own. This ensures audit logs are accessible to the information system security officer (ISSO) in the event of a central log processing failure.'
  desc 'check', 'At the command line, run the following command:

# grep "^num_logs" /etc/audit/auditd.conf

Expected result:

num_logs = 5

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/audit/auditd.conf

Add or change the "num_logs" line as follows:

num_logs = 5

At the command line, run the following commands:

# killproc auditd -TERM
# systemctl start auditd'
  impact 0.5
  tag check_id: 'C-60202r887253_chk'
  tag severity: 'medium'
  tag gid: 'V-256527'
  tag rid: 'SV-256527r887255_rule'
  tag stig_id: 'PHTN-30-000055'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-60145r887254_fix'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe auditd_conf do
    its('num_logs') { should cmp '5' }
  end
end
