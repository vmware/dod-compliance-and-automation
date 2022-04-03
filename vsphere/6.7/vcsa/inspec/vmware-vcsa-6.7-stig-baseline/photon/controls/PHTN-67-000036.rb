control 'PHTN-67-000036' do
  title "The Photon operating system must disable new accounts immediately upon
password expiration."
  desc  "Inactive identifiers pose a risk to systems and applications because
attackers may exploit an inactive identifier and potentially obtain undetected
access to the system. Owners of inactive accounts will not notice if
unauthorized access to their user account has been obtained.

    Disabling inactive accounts ensures that accounts that may not have been
responsibly removed are not available to attackers who may have compromised
their credentials.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep INACTIVE /etc/default/useradd

    Expected result:

    INACTIVE=0

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/default/useradd with a text editor.

    Remove any existing \"INACTIVE\" line and add the following line:

    INACTIVE=0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag gid: 'V-239108'
  tag rid: 'SV-239108r675132_rule'
  tag stig_id: 'PHTN-67-000036'
  tag fix_id: 'F-42278r675131_fix'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']

  describe parse_config_file('/etc/default/useradd') do
    its('INACTIVE') { should eq '0' }
  end
end
