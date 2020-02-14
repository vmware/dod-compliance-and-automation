control "PHTN-10-000017" do
  title "The Photon operating system audit log must be group-owned by root."
  desc  "Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit operating system activity.

    Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000059-GPOS-00029"
  tag gid: nil
  tag rid: "PHTN-10-000017"
  tag stig_id: "PHTN-10-000017"
  tag cci: "CCI-000164"
  tag nist: ["AU-9", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# (audit_log_file=$(grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//)
&& if [ -f \"${audit_log_file}\" ] ; then printf \"Log(s) found in
\"${audit_log_file%/*}\":\
\"; stat -c \"%n is group owned by %G\" ${audit_log_file%}*; else printf
\"audit log file(s) not found\
\"; fi)

If any audit log file is not group-owned by root, this is a finding.
"
  desc 'fix', "At the command line, execute the following command:

#  chown root:root <audit log file>

Replace <audit log file> with the log files not group owned by root."

  command('find /var/log/audit/ -maxdepth 1 -name "audit*.*"').stdout.split.each do | fname |
    describe file(fname) do
      its('group') { should cmp 'root' }
    end
  end

end

