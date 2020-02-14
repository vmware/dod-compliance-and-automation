control "PHTN-10-000057" do
  title "The Photon operating system must configure auditd to keep five rotated
log files."
  desc  "Audit logs are most useful when accessible by date, rather than size.
This can be acomplished through a combination of an audit log rotation cron
job, setting a reasonable number of logs to keep and configuring auditd to not
rotate the logs on it's own. This ensures that audit logs are accessible to the
ISSO in the event of a central log processing failure."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000341-GPOS-00132"
  tag gid: nil
  tag rid: "PHTN-10-000057"
  tag stig_id: "PHTN-10-000057"
  tag cci: "CCI-001849"
  tag nist: ["AU-4", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep \"^num_logs\" /etc/audit/auditd.conf

Expected result:

num_logs = 5

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Open /etc/audit/auditd.conf with a text editor. Add or change the
\"num_logs\" line as follows:

num_logs = 5

At the command line, execute the following command:

# service auditd reload"

  describe auditd_conf do
    its("num_logs") { should cmp '5'}
  end

end

