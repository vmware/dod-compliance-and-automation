# encoding: UTF-8

control 'PHTN-30-000042' do
  title 'The Photon operating system must audit all account modifications.'
  desc  "Once an attacker establishes access to a system, the attacker often
attempts to create a persistent method of reestablishing access.  One way to
accomplish this is for the attacker to modify an existing account.  Auditing
account modification actions provides logging that can be used for forensic
purposes."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E \"(usermod|groupmod)\"

    Expected result:

    -w /usr/sbin/usermod -p x -k usermod
    -w /usr/sbin/groupmod -p x -k groupmod

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the
following lines:

    -w /usr/sbin/usermod -p x -k usermod
    -w /usr/sbin/groupmod -p x -k groupmod

    At the command line, execute the following command to load the new audit
rules.

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag stig_id: 'PHTN-30-000042'
  tag cci: 'CCI-001403'
  tag nist: ['AC-2 (4)']

  describe auditd do
    its("lines") { should include %r{-w /usr/sbin/usermod -p x -k usermod} }
    its("lines") { should include %r{-w /usr/sbin/groupmod -p x -k groupmod} }
  end

end

