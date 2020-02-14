control "PHTN-10-000083" do
  title "The Photon operating system must configure sshd to disallow Generic
Security Service Application Program Interface (GSSAPI) authentication."
  desc  "GSSAPI authentication is used to provide additional authentication
mechanisms to applications. Allowing GSSAPI authentication through SSH exposes
the systems GSSAPI to remote hosts, increasing the attack surface of the
system."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000083"
  tag stig_id: "PHTN-10-000083"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# sshd -T|&grep -i GSSAPIAuthentication

Expected result:

GSSAPIAuthentication no

If the output does not match the expected result, this is a finding."
  desc 'fix', "Open /etc/ssh/sshd_config with a text editor and ensure that the
\"GSSAPIAuthentication\" line is uncommented and set to the following:

GSSAPIAuthentication no

At the command line, execute the following command:

# service sshd reload"

  describe command('sshd -T|&grep -i GSSAPIAuthentication') do
    its ('stdout.strip') { should cmp 'GSSAPIAuthentication no' }
  end

end

