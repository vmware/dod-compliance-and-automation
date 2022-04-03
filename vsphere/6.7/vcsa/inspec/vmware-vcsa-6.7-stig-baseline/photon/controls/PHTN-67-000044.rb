control 'PHTN-67-000044' do
  title 'The Photon operating system must audit all account modifications.'
  desc  "Once an attacker establishes access to a system, the attacker often
attempts to create a persistent method of reestablishing access.  One way to
accomplish this is for the attacker to modify an existing account. Auditing
account modification actions provides logging that can be used for forensic
purposes. "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E \"(usermod|groupmod)\"

    Expected result:

    -w /usr/sbin/usermod -p x -k usermod
    -w /usr/sbin/groupmod -p x -k groupmod

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the auditd service to be in a running state for
accurate results. Enabling the auditd service is done as part of a separate
control.
  "
  desc 'fix', "
    Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the
following lines:

    -w /usr/sbin/usermod -p x -k usermod
    -w /usr/sbin/groupmod -p x -k groupmod

    At the command line, execute the following command:

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag gid: 'V-251878'
  tag rid: 'SV-251878r816564_rule'
  tag stig_id: 'PHTN-67-000044'
  tag fix_id: 'F-55288r816563_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd do
    its('lines') { should include %r{-w /usr/sbin/usermod -p x -k usermod} }
    its('lines') { should include %r{-w /usr/sbin/groupmod -p x -k groupmod} }
  end
end
