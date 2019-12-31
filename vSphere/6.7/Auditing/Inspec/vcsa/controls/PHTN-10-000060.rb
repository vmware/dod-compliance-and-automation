control "PHTN-10-000060" do
  title "The Photon operating system must configure auditd to log space limit
problems to syslog."
  desc  "If security personnel are not notified immediately when storage volume
reaches 75% utilization, they are unable to plan for audit record storage
capacity expansion."
  tag severity: nil
  tag gtitle: "SRG-OS-000343-GPOS-00134"
  tag gid: nil
  tag rid: "PHTN-10-000060"
  tag stig_id: "PHTN-10-000060"
  tag fix_id: nil
  tag cci: "CCI-001855"
  tag nist: ["AU-5 (1)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AU-5 (1)"
  tag check: "At the command line, execute the following command:

# grep \"^space_left \" /etc/audit/auditd.conf

Expected result:

space_left = 75

If the output does not match the expected result, this is a finding."
  tag fix: "Open /etc/audit/auditd.conf with a text editor and ensure that the
\"space_left\" line is uncommented and set to the following:

space_left = 75

At the command line, execute the following command:

# service auditd reload"

  describe auditd_conf do
    its("space_left") { should cmp '75'}
  end

end

