control "PHTN-10-000047" do
  title "The Photon operating system must audit all account removal actions."
  desc  "When operating system accounts are removed, user accessibility is
affected. Accounts are utilized for identifying individual users or for
identifying the operating system processes themselves. In order to detect and
respond to events affecting user accessibility and system processing, operating
systems must audit account removal actions."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000241-GPOS-00091"
  tag gid: nil
  tag rid: "PHTN-10-00004"
  tag stig_id: "PHTN-10-000047"
  tag cci: "CCI-001405"
  tag nist: ["AC-2 (4)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# auditctl -l | grep -E \"(userdel|groupdel)\"

Expected result:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel

If the output does not match the expected result, this is a finding."
  desc 'fix', "At the command line, execute the following commands:

# echo '-w /usr/sbin/userdel -p x -k userdel' >>
/etc/audit/rules.d/audit.STIG.rules
# echo '-w /usr/sbin/groupdel -p x -k groupdel' >>
/etc/audit/rules.d/audit.STIG.rules
# /sbin/augenrules --load"

  describe auditd do
    its("lines") { should include %r{-w /usr/sbin/userdel -p x -k userdel} }
    its("lines") { should include %r{-w /usr/sbin/groupdel -p x -k groupdel} }
  end

end

