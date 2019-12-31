control "PHTN-10-000071" do
  title "The Photon operating system must generate audit records when the sudo
command is used."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  tag severity: nil
  tag gtitle: "SRG-OS-000458-GPOS-00203"
  tag gid: nil
  tag rid: "PHTN-10-000071"
  tag stig_id: "PHTN-10-000071"
  tag fix_id: nil
  tag cci: "CCI-000172"
  tag nist: ["AU-12 c", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AU-12 c"
  tag check: "At the command line, execute the following command:

# auditctl -l | grep sudo

Expected result:
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged

If the output does not match the expected result, this is a finding."
  tag fix: "At the command line, execute the following commands:

# echo '-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged' >> /etc/audit/rules.d/audit.STIG.rules
# /sbin/augenrules --load"

  describe auditd do
    its("lines") { should include %r{-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1} }
  end

end

