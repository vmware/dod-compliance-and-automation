control 'PHTN-30-000045' do
  title 'The Photon operating system must audit all account removal actions.'
  desc 'When operating system accounts are removed, user accessibility is affected. Accounts are used for identifying individual users or operating system processes. To detect and respond to events affecting user accessibility and system processing, operating systems must audit account removal actions.'
  desc 'check', 'At the command line, run the following command:

# auditctl -l | grep -E "(userdel|groupdel)"

Expected result:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel

If the output does not match the expected result, this is a finding.

Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done in control PHTN-30-000013.'
  desc 'fix', 'Navigate to and open:

/etc/audit/rules.d/audit.STIG.rules

Add the following lines:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel

At the command line, run the following command to load the new audit rules:

# /sbin/augenrules --load

Note: A new "audit.STIG.rules" file is provided for placement in "/etc/audit/rules.d" that contains all rules needed for auditd.

Note: An older "audit.STIG.rules" may exist if the file exists and references older "GEN" SRG IDs. This file can be removed and replaced as necessary with an updated one.'
  impact 0.5
  tag check_id: 'C-60195r887232_chk'
  tag severity: 'medium'
  tag gid: 'V-256520'
  tag rid: 'SV-256520r887234_rule'
  tag stig_id: 'PHTN-30-000045'
  tag gtitle: 'SRG-OS-000241-GPOS-00091'
  tag fix_id: 'F-60138r887233_fix'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']

  describe auditd do
    its('lines') { should include %r{-w /usr/sbin/userdel -p x -k userdel} }
    its('lines') { should include %r{-w /usr/sbin/groupdel -p x -k groupdel} }
  end
end
