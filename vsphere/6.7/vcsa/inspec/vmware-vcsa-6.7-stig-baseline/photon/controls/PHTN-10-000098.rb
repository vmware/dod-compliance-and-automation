control "PHTN-10-000098" do
  title "The Photon operating system must be configured so that all global
initialization scripts are protected from unauthorized modification."
  desc  "Local initialization files are used to configure the user's shell
environment upon login. Malicious modification of these files could compromise
accounts upon logon."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000098"
  tag stig_id: "PHTN-10-000098"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# find /etc/bash.bashrc /etc/profile /etc/profile.d/ -xdev -type f -a '(' -perm
-002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', "At the command line, execute the following commands for each
returned file:

# chmod o-w <file>
# chown root:root <file>"

  describe command ("find /etc/bash.bashrc /etc/profile /etc/profile.d/ -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \;") do
     its ('stdout') { should eq '' }
  end

end

