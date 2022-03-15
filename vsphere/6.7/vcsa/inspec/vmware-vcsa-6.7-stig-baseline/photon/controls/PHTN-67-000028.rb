control 'PHTN-67-000028' do
  title "The Photon operating system must be configured so that passwords for
new users are restricted to a 90-day maximum lifetime."
  desc  "Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If the operating system
does not limit the lifetime of passwords and force users to change their
passwords, there is the risk that the operating system passwords could be
compromised."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep \"^PASS_MAX_DAYS\" /etc/login.defs

    If the value of PASS_MAX_DAYS is greater than 90, this is a finding.
  "
  desc 'fix', "
    Open /etc/login.defs with a text editor.

    Modify the PASS_MAX_DAYS line to the following:

    PASS_MAX_DAYS   90
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-239100'
  tag rid: 'SV-239100r675108_rule'
  tag stig_id: 'PHTN-67-000028'
  tag fix_id: 'F-42270r675107_fix'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp '90' }
  end
end
