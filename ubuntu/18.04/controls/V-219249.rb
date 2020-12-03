control "V-219249" do
  title "The Ubuntu operating system must generate audit records for any usage of the
    fremovexattr system call."
  desc "Without generating audit records that are specific to the security and
    mission needs of the organization, it would be difficult to establish, correlate, and
    investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information system
    (e.g., module or policy filter).

    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210"
  impact 0.5
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "satisfies": nil
  tag "gid": "V-219249"
  tag "rid": "SV-219249r378727_rule"
  tag "stig_id": "UBTU-18-010326"
  tag "fix_id": "F-20973r305076_fix"
  tag "cci": [ "CCI-000172" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Verify if the Ubuntu operating system is configured to audit
    the execution of the \" fremovexattr\" system call, by running the following
    command:

    # sudo grep -w  fremovexattr /etc/audit/audit.rules

    -a always,exit -F arch=b64 -S  fremovexattr -F auid>=1000 -F auid!=4294967295 -k
    perm_mod

    -a always,exit -F arch=b64 -S  fremovexattr -F auid=0 -k perm_mod

    If the command does not return a line, or the line is commented out, this is a
    finding.
  "
  desc "fix", "Configure the Ubuntu operating system to audit the execution of
    the \" fremovexattr\" system call, by adding the following lines to
    \"/etc/audit/audit.rules\":

    -a always,exit -F arch=b64 -S  fremovexattr -F auid>=1000 -F auid!=4294967295 -k
    perm_mod

    -a always,exit -F arch=b64 -S  fremovexattr -F auid=0 -k perm_mod

    The audit daemon must be restarted for the changes to take effect. To restart
    the audit daemon, run the following command:

    # sudo systemctl restart auditd.service
  "

  if os.arch == "x86_64"
    describe auditd.syscall("fremovexattr").where { arch == "b64" } do
      its("action.uniq") { should eq ["always"] }
      its("list.uniq") { should eq ["exit"] }
    end
  end
  describe auditd.syscall("fremovexattr").where { arch == "b32" } do
    its("action.uniq") { should eq ["always"] }
    its("list.uniq") { should eq ["exit"] }
  end
end
