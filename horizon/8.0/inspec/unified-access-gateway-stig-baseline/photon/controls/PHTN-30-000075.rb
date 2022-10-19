control 'PHTN-30-000075' do
  title 'The Photon operating system must create a home directory for all new local interactive user accounts.'
  desc  'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep -i \"^create_home\" /etc/login.defs

    If there is no output or the output does not equal \"CREATE_HOME     yes\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/login.defs

    Ensure that the following is present and any exising CREATE_HOME line is removed:

    CREATE_HOME     yes
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000075'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe login_defs do
    its('CREATE_HOME') { should cmp 'yes' }
  end
end
