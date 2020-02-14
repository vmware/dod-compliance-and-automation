control "PHTN-10-000041" do
  title "The Photon operating system /var/log directory must be owned by root."
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state and can provide sensitive information to an unprivileged attacker."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000206-GPOS-00084"
  tag gid: nil
  tag rid: "PHTN-10-000041"
  tag stig_id: "PHTN-10-000041"
  tag cci: "CCI-001314"
  tag nist: ["SI-11 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# stat -c \"%n is owned by %U and group owned by %G\" /var/log

If the /var/log is not owned by root, this is a finding."
  desc 'fix', "At the command line, execute the following command:

# chown root:root /var/log"

  describe directory('/var/log') do
      its('owner') { should cmp 'root' }
  end

end

