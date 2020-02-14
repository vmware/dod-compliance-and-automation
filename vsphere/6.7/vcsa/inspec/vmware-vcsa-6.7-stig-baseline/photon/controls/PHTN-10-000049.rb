control "PHTN-10-000049" do
  title "The Photon operating system audit files and directories must have
correct permissions."
  desc  "Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000256-GPOS-00097"
  tag gid: nil
  tag rid: "PHTN-10-00004"
  tag stig_id: "PHTN-10-000049"
  tag cci: "CCI-001493"
  tag nist: ["AU-9", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# stat -c \"%n is owned by %U and group owned by %G\" /etc/audit/auditd.conf

If auditd.conf is not owned by root and group owned by root, this is a finding."
  desc 'fix', "At the command line, execute the following command:

# chown root:root /etc/audit/auditd.conf"

  describe file('/etc/audit/auditd.conf') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
  end

end

