control "PHTN-67-000046" do
  title 'The Photon operating system must audit all account disabling actions.'
  desc  "When operating system accounts are disabled, user accessibility is
affected. Accounts are used for identifying individual users or the operating
system processes themselves. To detect and respond to events affecting user
accessibility and system processing, operating systems must audit account
disabling actions."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep watch=/usr/bin/passwd

    Expected result:

    -w /usr/bin/passwd -p x -k passwd

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    At the command line, execute the following commands:

    # echo '-w /usr/bin/passwd -p x -k passwd' >>
/etc/audit/rules.d/audit.STIG.rules
    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000240-GPOS-00090'
  tag gid: 'V-239117'
  tag rid: 'SV-239117r675159_rule'
  tag stig_id: 'PHTN-67-000046'
  tag fix_id: 'F-42287r675158_fix'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']

  describe auditd do
    its("lines") { should include %r{-w /usr/bin/passwd -p x -k passwd} }
  end

end

