control 'PHTN-30-000045' do
  title 'The Photon operating system must audit all account removal actions.'
  desc  'When operating system accounts are removed, user accessibility is affected. Accounts are used for identifying individual users or for identifying the operating system processes themselves. In order to detect and respond to events affecting user accessibility and system processing, operating systems must audit account removal actions.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E \"(userdel|groupdel)\"

    Expected result:

    -w /usr/sbin/userdel -p x -k userdel
    -w /usr/sbin/groupdel -p x -k groupdel

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done in control PHTN-30-000013.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add the following lines:

    -w /usr/sbin/userdel -p x -k userdel
    -w /usr/sbin/groupdel -p x -k groupdel

    At the command line, execute the following command to load the new audit rules.

    # /sbin/augenrules --load

    Note: A new audit.STIG.rules file is provided as a supplemental document that can be placed in /etc/audit/rules.d that contains all rules needed for auditd.

    Note: An older audit.STIG.rules may exist if the file exists and references older \"GEN\" SRG IDs. This file can be removed and replaced as necessary with an updated one.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000241-GPOS-00091'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000045'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']

  describe auditd do
    its('lines') { should include %r{-w /usr/sbin/userdel -p x -k userdel} }
    its('lines') { should include %r{-w /usr/sbin/groupdel -p x -k groupdel} }
  end
end
