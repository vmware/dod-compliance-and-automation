control "PHTN-10-000001" do
  title "The Photon operating system must audit all account creations."
  desc  "Once an attacker establishes access to a system, the attacker often
attempts to create a persistent method of reestablishing access. One way to
accomplish this is for the attacker to create an account. Auditing account
creation actions provides logging that can be used for forensic purposes."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000004-GPOS-00004"
  tag gid: nil
  tag rid: "PHTN-10-000001"
  tag stig_id: "PHTN-10-000001"
  tag cci: "CCI-000018"
  tag nist: ["AC-2 (4)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# auditctl -l | grep -E \"(useradd|groupadd)\"

Expected result:

-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

If either useradd or groupadd are not listed with a permissions filter of at
least 'x', this is a finding."
  desc 'fix', "At the command line, execute the following commands:

# echo '-w /usr/sbin/useradd -p x -k useradd' >>
/etc/audit/rules.d/audit.STIG.rules
# echo '-w /usr/sbin/groupadd -p x -k groupadd' >>
/etc/audit/rules.d/audit.STIG.rules
# /sbin/augenrules --load"

  describe auditd do
    its("lines") { should include %r{-w /usr/sbin/useradd -p x -k useradd} }
    its("lines") { should include %r{-w /usr/sbin/groupadd -p x -k groupadd} }
  end

end

