control "PHTN-10-000090" do
  title "The Photon operating system must configure sshd to disallow
compression of the encrypted session stream."
  desc  "If compression is allowed in an SSH connection prior to
authentication, vulnerabilities in the compression software could result in
compromise of the system from an unauthenticated connection."
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000090"
  tag stig_id: "PHTN-10-000090"
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

# sshd -T|&grep -i Compression

Expected result:

Compression no

If the output does not match the expected result, this is a finding."
  tag fix: "Open /etc/ssh/sshd_config with a text editor and ensure that the
\"Compression\" line is uncommented and set to the following:

Compression no

At the command line, execute the following command:

# service sshd reload"

  describe command('sshd -T|&grep -i Compression') do
    its ('stdout.strip') { should cmp 'Compression no' }
  end

end

