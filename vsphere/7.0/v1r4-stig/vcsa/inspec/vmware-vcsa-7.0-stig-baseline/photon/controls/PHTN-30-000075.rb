control 'PHTN-30-000075' do
  title 'The Photon operating system must create a home directory for all new local interactive user accounts.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', 'At the command line, run the following command:

# grep -i "^create_home" /etc/login.defs

If there is no output or the output does not equal "CREATE_HOME     yes", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/login.defs

Ensure the following is present and any existing "CREATE_HOME" line is removed:

CREATE_HOME     yes'
  impact 0.5
  tag check_id: 'C-60220r887307_chk'
  tag severity: 'medium'
  tag gid: 'V-256545'
  tag rid: 'SV-256545r887309_rule'
  tag stig_id: 'PHTN-30-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60163r887308_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe login_defs do
    its('CREATE_HOME') { should cmp 'yes' }
  end
end
