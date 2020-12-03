control "V-219288" do
  title "The Ubuntu operating system must generate audit records when successful/unsuccessful
    use of unlinkat system call."
  desc "Without generating audit records that are specific to the security and mission
    needs of the organization, it would be difficult to establish, correlate, and investigate
    the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information
    system (e.g., module or policy filter)."
  impact 0.5
  tag "gtitle": "SRG-OS-000468-GPOS-00212"
  tag "satisfies": nil
  tag "gid": "V-219288"
  tag "rid": "SV-219288r381466_rule"
  tag "stig_id": "UBTU-18-010376"
  tag "fix_id": "F-21012r305193_fix"
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
  desc "check", "Verify the Ubuntu operating system generates audit records when
  successful/unsuccessful use of unlinkat system call.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep unlinkat

    -a always,exit -F arch=b64 -S unlinkat -F auid&gt;=1000 -F auid!=-1 -k delete
    -a always,exit -F arch=b32 -S unlinkat -F auid&gt;=1000 -F auid!=-1 -k delete

    If the command does not return lines that match the example or the lines are commented
    out, this is a finding.

    Notes:
    For 32-bit architectures, only the 32-bit specific output lines from the
    commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after it does
    not need to match the example output above.
  "
  desc "fix", "Configure the audit system to generate audit events when
    successful/unsuccessful use of unlinkat system call.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

    -a always,exit -F arch=b64 -S unlinkat -Fauid&gt;=1000 -F auid!=4294967295 -k delete
    -a always,exit -F arch=b32 -S unlinkat -F auid&gt;=1000 -F auid!=4294967295 -k delete

    Notes: For 32-bit architectures, only the 32-bit specific entries are required.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "

  if os.arch == "x86_64"
    describe auditd.syscall("unlinkat").where { arch == "b64" } do
      its("action.uniq") { should eq ["always"] }
      its("list.uniq") { should eq ["exit"] }
    end
  end
  describe auditd.syscall("unlinkat").where { arch == "b32" } do
    its("action.uniq") { should eq ["always"] }
    its("list.uniq") { should eq ["exit"] }
  end
end
