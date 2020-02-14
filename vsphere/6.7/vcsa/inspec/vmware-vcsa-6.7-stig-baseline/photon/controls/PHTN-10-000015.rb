control "PHTN-10-000015" do
  title "The Photon operating system audit log must have correct permissions."
  desc  "Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit operating system activity.

    Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000057-GPOS-00027"
  tag gid: nil
  tag rid: "PHTN-10-000015"
  tag stig_id: "PHTN-10-000015"
  tag cci: "CCI-000162"
  tag nist: ["AU-9", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# (audit_log_file=$(grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//)
&& if [ -f \"${audit_log_file}\" ] ; then printf \"Log(s) found in
\"${audit_log_file%/*}\":\
\"; stat -c \"%n permissions are %a\" ${audit_log_file%}*; else printf \"audit
log file(s) not found\
\"; fi)

If the permissions on any audit log file is more permissive than 0600, this is
a finding.
"
  desc 'fix', "At the command line, execute the following command:

#  chmod 0600 <audit log file>

Replace <audit log file> with the log files more permissive than 0600."

  command('find /var/log/audit/ -maxdepth 1 -name "audit*.*"').stdout.split.each do | fname |
    describe file(fname) do
      it { should_not be_more_permissive_than('0600') }
    end
  end

end

