control "PHTN-10-000115" do
  title "The Photon operating system must be configured to protect the SSH
public host key from unauthorized modification."
  desc  "If a public host key file is modified by an unauthorized user, the SSH
service may be compromised."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000115"
  tag stig_id: "PHTN-10-000115"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# stat -c \"%n permissions are %a and owned by %U:%G\" /etc/ssh/*key.pub

Expected result:

/etc/ssh/ssh_host_dsa_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_ecdsa_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_ed25519_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_rsa_key.pub permissions are 644 and owned by root:root

If the output does not match the expected result, this is a finding."
  desc 'fix', "At the command line, execute the following commands for each
returned file:

# chmod 644 <file>
# chown root:root <file>"

  command('find /etc/ssh/ -maxdepth 1 -name "*key.pub"').stdout.split.each do | fname |
      describe file(fname) do
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
        its('mode') { should cmp '0644' }
      end
  end

end

