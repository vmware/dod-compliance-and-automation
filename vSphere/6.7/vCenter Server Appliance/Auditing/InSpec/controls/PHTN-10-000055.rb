control "PHTN-10-000055" do
  title "The Photon operating system must configure sshd with a specific
ListenAddress."
  desc  "Without specifying a ListenAddress, sshd will listen on all
interfaces. In situations with multiple interfaces this may not be intended
behavior and could lead to offering remote access on an unapproved network."
  tag severity: nil
  tag gtitle: "SRG-OS-000297-GPOS-00115"
  tag gid: nil
  tag rid: "PHTN-10-000055"
  tag stig_id: "PHTN-10-000055"
  tag fix_id: nil
  tag cci: "CCI-002314"
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

# sshd -T|&grep -i ListenAddress

If the ListenAddress is not configured to the VCSA management IP, this is a
finding."
  tag fix: "Open /etc/ssh/sshd_config with a text editor and ensure that the
\"ListenAddress\" line is uncommented and set to a valid local IP:

Example:

ListenAddress 169.254.1.2

Replace '169.254.1.2' with the management address of the VCSA.

At the command line, execute the following command:

# service sshd reload"

  describe command('sshd -T|&grep -i ListenAddress') do
    its ('stdout.strip') { should cmp "ListenAddress #{input('photonIp')}" }
  end

end

