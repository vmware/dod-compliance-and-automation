control "PHTN-10-000016" do
  title "The Photon operating system audit log must be owned by root."
  desc  "Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit operating system activity.

    Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000058-GPOS-00028"
  tag gid: nil
  tag rid: "PHTN-10-000016"
  tag stig_id: "PHTN-10-000016"
  tag cci: "CCI-000163"
  tag nist: ["AU-9", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# (audit_log_file=$(grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//)
&& if [ -f \"${audit_log_file}\" ] ; then printf \"Log(s) found in
\"${audit_log_file%/*}\":\
\"; stat -c \"%n is owned by %U\" ${audit_log_file%}*; else printf \"audit log
file(s) not found\
\"; fi)

If any audit log file is not owned by root, this is a finding.
"
  desc 'fix', "At the command line, execute the following command:

#  chown root:root <audit log file>

Replace <audit log file> with the log files not owned by root."

  command('find /var/log/audit/ -maxdepth 1 -name "audit*.*"').stdout.split.each do | fname |
    describe file(fname) do
      its('owner') { should cmp 'root' }
    end
  end

end

