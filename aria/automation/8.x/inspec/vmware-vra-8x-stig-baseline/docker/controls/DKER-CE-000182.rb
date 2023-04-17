control 'DKER-CE-000182' do
  title 'Docker CE must be configured to update iptables rules.'
  desc  'Allowing docker to modify iptables rules ensures that incoming packets are inspected and either allowed or denied based on intentional network policy. This is the default behavior in Docker and must not be turned off.'
  desc  'rationale', ''
  desc  'check', "
    To verify the Docker daemon is configured to integrate with iptables, execute the following commands:

    # ps -ef | grep dockerd
    # grep iptables /etc/docker/daemon.json

    If no output is returned from either command, this is NOT a finding.

    If iptables is set to false as either an argument on the dockerd process or defined in the daemon.json file, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/docker/daemon.json

    Add or update the following option as seen in the example below.

      \"iptables\": true

    Restart the docker daemon by running the following command:

    # systemctl restart docker.service

    Note: This option can also be completely removed as an argument and removed from the daemon.json file as it is the default if not specified.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000182'
  tag fix_id: nil
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe.one do
    result = command('ps -ef | grep -v grep | grep dockerd | grep iptables')
    describe 'Checking if iptables is configured by daemon parameter' do
      it '{ Daemon must not include an iptables override at launch }' do
        expect(result.stdout).to be_nil.or eq('')
      end
    end
    describe 'Checking if iptables is configured by daemon parameter' do
      it '{ If daemon is set with iptables parameter it must not be set to false }' do
        expect(result.stdout).not_to include 'false'
      end
    end
  end

  daemon_conf = file('/etc/docker/daemon.json')
  if daemon_conf.exist?
    describe.one do
      j = json('/etc/docker/daemon.json')
      describe 'Checking if iptables is configured in conf file' do
        it '{ Conf file must not include an iptables override }' do
          expect(j['iptables']).to be_nil
        end
      end
      describe 'Checking if iptables is configured in conf file' do
        it '{ If conf file includes an iptables override it must not be set to false }' do
          expect(j['iptables']).to eq(true)
        end
      end
    end
  end
end
