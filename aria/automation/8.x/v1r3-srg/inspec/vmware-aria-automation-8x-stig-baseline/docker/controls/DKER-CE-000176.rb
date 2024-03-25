control 'DKER-CE-000176' do
  title 'Docker CE must protect the docker service from unauthorized changes.'
  desc  'The docker service file contains sensitive parameters that may alter the behavior of docker daemon. Hence, it must be writable only by root to maintain the integrity of the file.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c %a:%U:%G /usr/lib/systemd/system/docker.service

    Expected result:

    644:root:root

    If the permissions are not set to 644 or more restrictive, this is a finding.

    If the file ownership is not set to root:root, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # chmod 644 /usr/lib/systemd/system/docker.service
    # chown root:root /usr/lib/systemd/system/docker.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000305'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000176'
  tag fix_id: nil
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe file('/usr/lib/systemd/system/docker.service') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0644') }
  end
end
