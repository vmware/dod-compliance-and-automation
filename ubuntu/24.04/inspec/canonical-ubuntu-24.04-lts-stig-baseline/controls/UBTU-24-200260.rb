control 'UBTU-24-200260' do
  title 'Ubuntu 24.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.

'
  desc 'check', 'Verify the account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity with the following command:

Check the account inactivity value by performing the following command:

$ grep INACTIVE /etc/default/useradd
INACTIVE=35

If "INACTIVE" is not set to a value 0<[VALUE]<=35, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to disable account identifiers after 35 days of inactivity after the password expiration.

Run the following command to change the configuration for adduser:

$ sudo useradd -D -f 35

Note: DOD recommendation is 35 days, but a lower value is acceptable. The value "0" will disable the account immediately after the password expires.'
  impact 0.5
  tag check_id: 'C-74716r1066536_chk'
  tag severity: 'medium'
  tag gid: 'V-270683'
  tag rid: 'SV-270683r1066538_rule'
  tag stig_id: 'UBTU-24-200260'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-74617r1066537_fix'
  tag satisfies: ['SRG-OS-000118-GPOS-00060', 'SRG-OS-000590-GPOS-00110']
  tag 'documentable'
  tag cci: ['CCI-003627', 'CCI-003628']
  tag nist: ['AC-2 (3) (a)', 'AC-2 (3) (b)']

  config_file = input('useradd_configuration')
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
