control 'PHTN-40-000209' do
  title 'The Photon operating system must create a home directory for all new local interactive user accounts.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', %q(At the command line, run the following command to verify a home directory is created for all new user accounts:

# grep '^CREATE_HOME' /etc/login.defs

Example result:

CREATE_HOME yes

If the "CREATE_HOME" option is not set to "yes", is missing or commented out, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/login.defs

Add or update the following line:

CREATE_HOME yes'
  impact 0.5
  tag check_id: 'C-62612r933675_chk'
  tag severity: 'medium'
  tag gid: 'V-258872'
  tag rid: 'SV-258872r933677_rule'
  tag stig_id: 'PHTN-40-000209'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62521r933676_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe login_defs do
    its('CREATE_HOME') { should cmp 'yes' }
  end
end
