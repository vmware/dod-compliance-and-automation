control 'PHTN-30-000035' do
  title 'The Photon operating system must disable new accounts immediately upon password expiration.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Disabling inactive accounts ensures accounts that may not have been responsibly removed are not available to attackers who may have compromised their credentials.'
  desc 'check', 'At the command line, run the following command:

# grep INACTIVE /etc/default/useradd

Expected result:

INACTIVE=0

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/default/useradd

Remove an existing "INACTIVE" line and add the following line:

INACTIVE=0'
  impact 0.5
  tag check_id: 'C-60186r887205_chk'
  tag severity: 'medium'
  tag gid: 'V-256511'
  tag rid: 'SV-256511r887207_rule'
  tag stig_id: 'PHTN-30-000035'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-60129r887206_fix'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']

  describe parse_config_file('/etc/default/useradd') do
    its('INACTIVE') { should eq '0' }
  end
end
