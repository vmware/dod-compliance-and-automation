# encoding: UTF-8

control 'PHTN-30-000044' do
  title 'The Photon operating system must audit all account disabling actions.'
  desc  "When operating system accounts are disabled, user accessibility is
affected. Accounts are utilized for identifying individual users or for
identifying the operating system processes themselves. In order to detect and
respond to events affecting user accessibility and system processing, operating
systems must audit account disabling actions."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

     # auditctl -l | grep \"w /usr/bin/passwd\"

     Expected result:

     -w /usr/bin/passwd -p x -k passwd

     If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the
following lines:

    -w /usr/bin/passwd -p x -k passwd

     At the command line, execute the following command to load the new audit
rules.

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000240-GPOS-00090'
  tag stig_id: 'PHTN-30-000044'
  tag cci: 'CCI-001404'
  tag nist: ['AC-2 (4)']

  describe auditd do
    its("lines") { should include %r{-w /usr/bin/passwd -p x -k passwd} }
  end

end

