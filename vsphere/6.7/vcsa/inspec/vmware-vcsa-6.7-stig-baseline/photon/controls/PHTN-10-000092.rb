control "PHTN-10-000092" do
  title "The Photon operating system must configure sshd to ignore
user-specific trusted hosts lists."
  desc  "SSH trust relationships enable trivial lateral spread after a host
compromise and therefore must be explicitly disabled. Individual users can have
a local list of trusted remote machines which must also be ignored while
disabling host-based authentication generally."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000092"
  tag stig_id: "PHTN-10-000092"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# sshd -T|&grep -i IgnoreRhosts

Expected result:

IgnoreRhosts yes

If the output does not match the expected result, this is a finding."
  desc 'fix', "Open /etc/ssh/sshd_config with a text editor and ensure that the
\"IgnoreRhosts\" line is uncommented and set to the following:

IgnoreRhosts yes

At the command line, execute the following command:

# service sshd reload"

  describe command('sshd -T|&grep -i IgnoreRhosts') do
    its ('stdout.strip') { should cmp 'IgnoreRhosts yes' }
  end

end

