control 'UBTU-22-411030' do
  title 'Ubuntu 22.04 LTS must be able to enforce a 180-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If Ubuntu 22.04 LTS does not limit the lifetime of passwords and force users to change their passwords, there is the risk that Ubuntu 22.04 LTS passwords could be compromised.'
  desc 'check', 'Verify Ubuntu 22.04 LTS enforces a 180-day maximum password lifetime for new user accounts by using the following command:

     $ grep -i pass_max_days /etc/login.defs
     PASS_MAX_DAYS    180

If "PASS_MAX_DAYS" is less than "180", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce a 180-day maximum password lifetime.

Add or modify the following line in the "/etc/login.defs" file:

PASS_MAX_DAYS    180'
  impact 0.5
  tag check_id: 'C-64275r1273629_chk'
  tag severity: 'medium'
  tag gid: 'V-260546'
  tag rid: 'SV-260546r1273631_rule'
  tag stig_id: 'UBTU-22-411030'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-64183r1273630_fix'
  tag 'documentable'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 180 }
  end
end
