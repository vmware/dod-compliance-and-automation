# encoding: UTF-8

control 'PHTN-30-000045' do
  title 'The Photon operating system must audit all account removal actions.'
  desc  "When operating system accounts are removed, user accessibility is
affected. Accounts are used for identifying individual users or for identifying
the operating system processes themselves. In order to detect and respond to
events affecting user accessibility and system processing, operating systems
must audit account removal actions."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E \"(userdel|groupdel)\"

    Expected result:

    -w /usr/sbin/userdel -p x -k userdel
    -w /usr/sbin/groupdel -p x -k groupdel

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add the following lines:

    -w /usr/sbin/userdel -p x -k userdel
    -w /usr/sbin/groupdel -p x -k groupdel

    At the command line, execute the following command to load the new audit
rules.

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000241-GPOS-00091'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000045'
  tag fix_id: nil
  tag cci: 'CCI-001405'
  tag nist: ['AC-2 (4)']

  describe auditd do
    its("lines") { should include %r{-w /usr/sbin/userdel -p x -k userdel} }
    its("lines") { should include %r{-w /usr/sbin/groupdel -p x -k groupdel} }
  end

end

