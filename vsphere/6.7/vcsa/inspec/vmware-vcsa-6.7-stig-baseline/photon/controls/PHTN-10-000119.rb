control "PHTN-10-000119" do
  title "The Photon operating system must protect sshd configuration from
unauthorized access."
  desc  "The sshd_config file contains all the configuration items for sshd.
Incorrect or malicious configuration of sshd can allow unauthorized access to
the system, insecure communication, limited forensic trail, etc. "
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000119"
  tag stig_id: "PHTN-10-000119"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# stat -c \"%n permissions are %a and owned by %U:%G\" /etc/ssh/sshd_config

Expected result:

/etc/ssh/sshd_config permissions are 600 and owned by root:root

If the output does not match the expected result, this is a finding."
  desc 'fix', "At the command line, execute the following commands:

# chmod 600 /etc/ssh/sshd_config
# chown root:root /etc/ssh/sshd_config"

  describe file('/etc/ssh/sshd_config') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0600' }
  end

end

