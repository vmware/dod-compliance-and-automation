control 'DKER-CE-000175' do
  title 'Docker CE must protect /etc/docker/daemon.json from unauthorized changes.'
  desc  '/etc/docker/daemon.json file contains sensitive parameters that may alter the behavior of docker daemon. Hence, it must be owned and group-owned by root to maintain the integrity of the file.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c %a:%U:%G /etc/docker/daemon.json

    Expected result:

    644:root:root

    If the permissions are not set to 644 or more restrictive, this is a finding.

    If the file ownership is not set to root:root, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # chmod 644 /etc/docker/daemon.json
    # chown root:root /etc/docker/daemon.json
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000305'
  tag gid: 'V-DKER-CE-000175'
  tag rid: 'SV-DKER-CE-000175'
  tag stig_id: 'DKER-CE-000175'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  conf = file('/etc/docker/daemon.json')
  if conf.exist?
    describe file('/etc/docker/daemon.json') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      it { should_not be_more_permissive_than('0644') }
    end
  else
    describe 'Default config file not present' do
      skip 'Default config file not present'
    end
  end
end
