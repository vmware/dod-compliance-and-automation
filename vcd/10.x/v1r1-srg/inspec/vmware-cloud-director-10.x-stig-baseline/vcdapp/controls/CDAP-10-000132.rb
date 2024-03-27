control 'CDAP-10-000132' do
  title 'Cloud Director must disable root SSH logins.'
  desc  'Logging on with a user-specific account provides individual accountability for actions performed on the system. Users must log in with their individual accounts and elevate to root as necessary. Disallowing root SSH login also reduces the distribution of the root password to users who may not otherwise need that level of privilege.'
  desc  'rationale', ''
  desc  'check', "
    Verify root SSH logins are disabled by running the following command on each appliance:

    # sshd -T|&grep -i PermitRootLogin

    Expected result:

    permitrootlogin no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/appliance/bin/disable_root_login.sh
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CDAP-10-000132'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('sshd -T|&grep -i PermitRootLogin') do
    its('stdout.strip') { should cmp 'permitrootlogin no' }
  end
end
