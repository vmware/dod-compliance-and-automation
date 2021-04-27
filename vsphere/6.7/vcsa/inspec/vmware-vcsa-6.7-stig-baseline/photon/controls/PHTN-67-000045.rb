control "PHTN-67-000045" do
  title 'The Photon operating system must audit all account modifications.'
  desc  "Once an attacker establishes access to a system, the attacker often
attempts to create a persistent method of reestablishing access. One way to
accomplish this is for the attacker to modify an existing account. Auditing
account modification actions provides logging that can be used for forensic
purposes.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E
\"(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)\"

    Expected result:

    -w /etc/passwd -p wa -k passwd
    -w /etc/shadow -p wa -k shadow
    -w /etc/group -p wa -k group
    -w /etc/gshadow -p wa -k gshadow

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    At the command line, execute the following commands:

    # echo '-w /etc/passwd -p w -k passwd' >>
/etc/audit/rules.d/audit.STIG.rules
    # echo '-w /etc/shadow -p w -k shadow' >>
/etc/audit/rules.d/audit.STIG.rules
    # echo '-w /etc/group -p w -k group' >> /etc/audit/rules.d/audit.STIG.rules
    # echo '-w /etc/gshadow -p w -k gshadow' >>
/etc/audit/rules.d/audit.STIG.rules
    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag satisfies: ['SRG-OS-000239-GPOS-00089', 'SRG-OS-000303-GPOS-00120',
'SRG-OS-000304-GPOS-00121']
  tag gid: 'V-239116'
  tag rid: 'SV-239116r675156_rule'
  tag stig_id: 'PHTN-67-000045'
  tag fix_id: 'F-42286r675155_fix'
  tag cci: ['CCI-001403', 'CCI-002130', 'CCI-002132']
  tag nist: ['AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']

  describe auditd do
    its("lines") { should include %r{-w /usr/sbin/usermod -p x -k usermod} }
    its("lines") { should include %r{-w /usr/sbin/groupmod -p x -k groupmod} }
  end

end

