control 'PHTN-67-000026' do
  title "The Photon operating system must store only encrypted representations
of passwords."
  desc  "Passwords must be protected at all times via strong, one-way
encryption. If passwords are not encrypted, they can be plainly read (i.e.,
clear text) and easily compromised. If they are encrypted with a weak cipher,
those passwords are much more vulnerable to offline brute forcing attacks."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep SHA512 /etc/login.defs|grep -v \"#\"

    Expected result:

    ENCRYPT_METHOD SHA512

    If there is no output or if the output does match the expected result, this
is a finding.
  "
  desc 'fix', "
    Open /etc/login.defs with a text editor.

    Add or replace the ENCRYPT_METHOD line as follows:

    ENCRYPT_METHOD SHA512
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag gid: 'V-239098'
  tag rid: 'SV-239098r675102_rule'
  tag stig_id: 'PHTN-67-000026'
  tag fix_id: 'F-42268r675101_fix'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  describe login_defs do
    its('ENCRYPT_METHOD') { should cmp 'SHA512' }
  end
end
