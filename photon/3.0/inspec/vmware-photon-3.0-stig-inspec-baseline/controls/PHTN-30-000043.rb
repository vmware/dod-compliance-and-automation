control 'PHTN-30-000043' do
  title 'The Photon operating system must audit all account modifications.'
  desc  'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access.  One way to accomplish this is for the attacker to modify an existing account.  Auditing account modification actions provides logging that can be used for forensic purposes.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E \"(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)\"

    Expected result:

    -w /etc/passwd -p wa -k passwd
    -w /etc/shadow -p wa -k shadow
    -w /etc/group -p wa -k group
    -w /etc/gshadow -p wa -k gshadow

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done in control PHTN-30-000013.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add the following lines:

    -w /etc/passwd -p wa -k passwd
    -w /etc/shadow -p wa -k shadow
    -w /etc/group -p wa -k group
    -w /etc/gshadow -p wa -k gshadow

    At the command line, execute the following command to load the new audit rules.

    # /sbin/augenrules --load

    Note: A new audit.STIG.rules file is provided as a supplemental document that can be placed in /etc/audit/rules.d that contains all rules needed for auditd.

    Note: An older audit.STIG.rules may exist if the file exists and references older \"GEN\" SRG IDs. This file can be removed and replaced as necessary with an updated one.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag satisfies: ['SRG-OS-000303-GPOS-00120']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000043'
  tag cci: ['CCI-001403', 'CCI-002130']
  tag nist: ['AC-2 (4)']

  describe auditd do
    its('lines') { should include %r{-w /etc/passwd -p wa -k passwd} }
    its('lines') { should include %r{-w /etc/shadow -p wa -k shadow} }
    its('lines') { should include %r{-w /etc/group -p wa -k group} }
    its('lines') { should include %r{-w /etc/gshadow -p wa -k gshadow} }
  end
end
