control 'DKER-CE-000187' do
  title 'Docker CE must use the default base device size.'
  desc  'Altering the default base size could lead to overallocation of storage and cause a denial of service.'
  desc  'rationale', ''
  desc  'check', "
    To verify the Docker daemon is configured with the default base size, execute the following commands:

    # ps -ef | grep dockerd
    # grep dm.basesize /etc/docker/daemon.json

    If dm-basesize is configured either as an argument on the dockerd process or defined in the daemon.json file, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/docker/daemon.json

    Find the \"dm-basesize\" line and remove it.

    Restart the docker daemon by running the following command:

    # systemctl restart docker.service

    Note: This setting may also be specified as an argument to the Docker daemon service and must be removed there if specified in that manner.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000187'
  tag fix_id: nil
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe.one do
    result = command('ps -ef | grep -v grep | grep dockerd | grep dm-basesize')
    describe 'Checking if dm-basesize is configured by daemon parameter' do
      it 'Daemon must not include a dm-basesize override at launch' do
        expect(result.stdout).to be_nil.or eq('')
      end
    end

    daemon_conf = file('/etc/docker/daemon.json')
    if daemon_conf.exist?
      describe 'Checking if iptables is configured in conf file' do
        it 'Conf file must not include an iptables override' do
          expect(j['iptables']).to be_nil
        end
      end
    end
  end
end
