control 'UBTU-22-411035' do
  title 'Ubuntu 22.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity by using the following command:

Check the account inactivity value by performing the following command:

     $ grep INACTIVE /etc/default/useradd
     INACTIVE=35

If "INACTIVE" is set to "-1" or is not set to "35", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to disable account identifiers after 35 days of inactivity after the password expiration.

Run the following command to change the configuration for adduser:

     $ sudo useradd -D -f 35

Note: DOD recommendation is 35 days, but a lower value is acceptable. The value "0" will disable the account immediately after the password expires.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64276r953452_chk'
  tag severity: 'medium'
  tag gid: 'V-260547'
  tag rid: 'SV-260547r1015009_rule'
  tag stig_id: 'UBTU-22-411035'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-64184r953453_fix'
  tag 'documentable'
  tag cci: ['CCI-000795', 'CCI-003627', 'CCI-003628']
  tag nist: ['IA-4 e', 'AC-2 (3) (a)', 'AC-2 (3) (b)']

  config_file = '/etc/default/useradd'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('INACTIVE') { should cmp > '0' }
      its('INACTIVE') { should cmp <= 35 }
    end
  else
    describe("#{config_file} exists") do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
