control "V-219292" do
  title "The Ubuntu operating system must generate audit records when unloading 
    dynamic kernel modules."
  desc "Without generating audit records that are specific to the security
    and mission needs of the organization, it would be difficult to establish,
    correlate, and investigate the events relating to an incident or identify those
    responsible for one.

    Audit records can be generated from various components within the information
    system (e.g., module or policy filter).
  "

  impact 0.5
  tag "gtitle": "SRG-OS-000471-GPOS-00216"
  tag "satisfies": nil
  tag "gid": "V-219292"
  tag "rid": "SV-219292r381475_rule"
  tag "stig_id": "UBTU-18-010380"
  tag "fix_id": "F-21016r305205_fix"
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
  desc "check", "Verify the Ubuntu operating system generates an audit record
    when successful/unsuccessful attempts to use the \"delete_module\" command
    occur.

    Check that the following calls are being audited by performing the following
    command to check the file system rules in \"/etc/audit/audit.rules\":

    # sudo grep -w \"delete_module\" /etc/audit/audit.rules

    -a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295
    -k module_chng

    If the command does not return a line, or the line is commented out, this is a
    finding.
  "
  desc "fix", "Configure the audit system to generate an audit event for any
    successful/unsuccessful use of the \"delete_module\" command.

    Add or update the following rules in the \"/etc/audit/audit.rules\" file:

    -a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295
    -k module_chng

    The audit daemon must be restarted for the changes to take effect. To restart
    the audit daemon, run the following command:

    # sudo systemctl restart auditd.service
  "

  if os.arch == "x86_64"
    describe auditd.syscall("delete_module").where { arch == "b64" } do
      its("action.uniq") { should eq ["always"] }
      its("list.uniq") { should eq ["exit"] }
    end
  end
  describe auditd.syscall("delete_module").where { arch == "b32" } do
    its("action.uniq") { should eq ["always"] }
    its("list.uniq") { should eq ["exit"] }
  end
end
