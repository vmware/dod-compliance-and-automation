control "PHTN-10-000049" do
  title "The Photon operating system audit files and directories must have
correct permissions."
  desc  "Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information."
  tag severity: nil
  tag gtitle: "SRG-OS-000256-GPOS-00097"
  tag gid: nil
  tag rid: "PHTN-10-000049"
  tag stig_id: "PHTN-10-000049"
  tag fix_id: nil
  tag cci: "CCI-001493"
  tag nist: ["AU-9", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AU-9"
  tag check: "At the command line, execute the following command:

# stat -c \"%n is owned by %U and group owned by %G\" /etc/audit/auditd.conf

If auditd.conf is not owned by root and group owned by root, this is a finding."
  tag fix: "At the command line, execute the following command:

# chown root:root /etc/audit/auditd.conf"

  describe file('/etc/audit/auditd.conf') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
  end

end

