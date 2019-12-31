control "PHTN-10-000006" do
  title "The Photon operating system must have the sshd SyslogFacility set to
authpriv."
  desc  "Automated monitoring of remote access sessions allows organizations to
detect cyber attacks and ensure ongoing compliance with remote access policies
by auditing connection activities."
  tag severity: nil
  tag gtitle: "SRG-OS-000032-GPOS-00013"
  tag gid: nil
  tag rid: "PHTN-10-000006"
  tag stig_id: "PHTN-10-000006"
  tag fix_id: nil
  tag cci: "CCI-000067"
  tag nist: ["AC-17 (1)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AC-17 (1)"
  tag check: "At the command line, execute the following command:

# sshd -T|&grep -i SyslogFacility

Expected result:

syslogfacility AUTHPRIV

If there is no output or if the output does not match expected result, this is
a finding.
"
  tag fix: "Open /etc/ssh/sshd_config with a text editor and ensure that the
\"SyslogFacility\" line is uncommented and set to the following:

SyslogFacility AUTHPRIV

At the command line, execute the following command:

# service sshd reload"

  describe command('sshd -T|&grep -i syslogfacility') do
    its ('stdout.strip') { should cmp 'syslogfacility AUTHPRIV' }
  end

end

