control "PHTN-10-000072" do
  title "The Photon operating system must generate audit records when
successful/unsuccessful logon attempts occur."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  tag severity: nil
  tag gtitle: "SRG-OS-000470-GPOS-00214"
  tag gid: nil
  tag rid: "PHTN-10-000072"
  tag stig_id: "PHTN-10-000072"
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

# auditctl -l | grep -E \"faillog|lastlog|tallylog\"

Expected result:

-w /var/log/faillog -p wa
-w /var/log/lastlog -p wa
-w /var/log/tallylog -p wa

If the output does not match the expected result, this is a finding."
  tag fix: "At the command line, execute the following commands:

# echo '-w /var/log/faillog -p wa' >> /etc/audit/rules.d/audit.STIG.rules
# echo '-w /var/log/lastlog -p wa' >> /etc/audit/rules.d/audit.STIG.rules
# echo '-w /var/log/tallylog -p wa' >> /etc/audit/rules.d/audit.STIG.rules
# /sbin/augenrules --load"

  describe auditd do
    its("lines") { should include %r{-w /var/log/faillog -p wa} }
    its("lines") { should include %r{-w /var/log/lastlog -p wa} }
    its("lines") { should include %r{-w /var/log/tallylog -p wa} }
  end

end

