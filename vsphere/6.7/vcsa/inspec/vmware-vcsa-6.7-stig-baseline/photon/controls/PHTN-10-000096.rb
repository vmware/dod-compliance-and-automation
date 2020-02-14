control "PHTN-10-000096" do
  title "The Photon operating system must be configured so that the /etc/skel
default scripts are protected from unauthorized modification."
  desc  "If the skeleton files are not protected, unauthorized personnel could
change user startup parameters and possibly jeopardize user files."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000096"
  tag stig_id: "PHTN-10-000096"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# stat -c \"%n permissions are %a and owned by %U:%G\" /etc/skel/.[^.]*

Expected result:

/etc/skel/.bash_logout permissions are 750 and owned by root:root
/etc/skel/.bash_profile permissions are 644 and owned by root:root
/etc/skel/.bashrc permissions are 750 and owned by root:root

If the output does not match the expected result, this is a finding."
  desc 'fix', "At the command line, execute the following commands:

# chmod 750 /etc/skel/.bash_logout
# chmod 644 /etc/skel/.bash_profile
# chmod 750 /etc/skel/.bashrc
# chown root:root /etc/skel/.bash_logout
# chown root:root /etc/skel/.bash_profile
# chown root:root /etc/skel/.bashrc"

  describe file('/etc/skel/.bash_logout') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0750' }
  end

  describe file('/etc/skel/.bash_profile') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0644' }
  end

  describe file('/etc/skel/.bashrc') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0750' }
  end

end

