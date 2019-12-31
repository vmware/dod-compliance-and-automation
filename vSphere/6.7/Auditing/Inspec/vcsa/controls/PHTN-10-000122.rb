control "PHTN-10-000122" do
  title "The Photon operating system must configure sshd to disallow
HostbasedAuthentication."
  desc  "SSH trust relationships enable trivial lateral spread after a host
compromise and therefore must be explicitly disabled."
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00229"
  tag gid: nil
  tag rid: "PHTN-10-000122"
  tag stig_id: "PHTN-10-000122"
  tag fix_id: nil
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "CM-6 b"
  tag check: "At the command line, execute the following command:

# sshd -T|&grep -i HostbasedAuthentication

Expected result:

hostbasedauthentication no

If the output does not match the expected result, this is a finding."
  tag fix: "Open /etc/ssh/sshd_config with a text editor and ensure that the
\"HostbasedAuthentication\" line is uncommented and set to the following:

HostbasedAuthentication no

At the command line, execute the following command:

# service sshd reload"

  describe command('sshd -T|&grep -i HostbasedAuthentication') do
      its ('stdout.strip') { should cmp 'HostbasedAuthentication no' }
  end

end

