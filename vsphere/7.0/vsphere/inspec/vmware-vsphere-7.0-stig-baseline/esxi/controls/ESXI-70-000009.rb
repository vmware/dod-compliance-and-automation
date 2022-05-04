control 'ESXI-70-000009' do
  title 'The ESXi host SSH daemon must be configured with the DoD logon banner.'
  desc  'The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # /usr/lib/vmware/openssh/bin/sshd -T|grep banner

    Expected result:

    banner /etc/issue

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell,  add or correct the following line in \"/etc/ssh/sshd_config\":

    Banner /etc/issue
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-VMM-000060'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000009'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
