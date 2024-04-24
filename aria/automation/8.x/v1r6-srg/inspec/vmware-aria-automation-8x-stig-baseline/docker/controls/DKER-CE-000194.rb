control 'DKER-CE-000194' do
  title 'Docker CE must configure the number of retries if a restart policy is defined.'
  desc  "
    Using the --restart flag in docker run command, a restart policy must be specified that controls how a container is or is not restarted on exit. Choose the on-failure restart policy and limit the restart attempts to 5.

    If the container attempts to restart indefinitely, it could possibly lead to a denial of service on the host. It could be an easy way to do a distributed denial of service attack especially if there are many containers on the same host. Additionally, ignoring the exit status of the container and always attempting to restart the container leads to non-investigation of the root cause behind containers getting terminated. If a container gets terminated, investigate the reason behind it instead of just attempting to restart it indefinitely.

    Thus, it is recommended to use on-failure restart policy and limit it to maximum of 5 restart attempts. The container would then attempt to restart only 5 times.

    By default, containers are not configured with restart policies. Hence, containers do not attempt to restart on their own.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: RestartPolicyName={{ .HostConfig.RestartPolicy.Name }} MaximumRetryCount={{ .HostConfig.RestartPolicy.MaximumRetryCount }}'

    If RestartPolicyName is blank or no and MaximumRetryCount=0, this is not a finding.

    If RestartPolicyName is always, this is not a finding.

    If RestartPolicyName is on-failure and MaximumRetryCount is > 5, this is a finding.
  "
  desc  'fix', "
    For containers with restart policies that result in a finding, do the following:

    Stop the container and then start the container without specifying the --restart argument or if specified make sure it conforms to the rules laid out in the check text.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-DKER-CE-000194'
  tag rid: 'SV-DKER-CE-000194'
  tag stig_id: 'DKER-CE-000194'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  docker.containers.running?.ids.each do |id|
    pol = docker.object(id).HostConfig.RestartPolicy
    describe.one do
      describe 'Checking allowable values for Resource Policy Name and MaximumRetryCount' do
        it '{ Restart Policy Name blank or no and MaximumRetryCount 0 }' do
          expect(pol.Name).to eq('').or eq(nil).or eq('no')
          expect(pol.MaximumRetryCount).to eq(0)
        end
      end
      describe 'Checking allowable values for Resource Policy Name and MaximumRetryCount' do
        it "{ Restart Policy Name 'always' }" do
          expect(pol.Name).to eq('always')
        end
      end
      describe 'Checking allowable values for Resource Policy Name and MaximumRetryCount' do
        it "{ If Restart Policy Name 'on-failure' and MaximumRetryCount not greater than 5 }" do
          expect(pol.Name).to eq('on-failure')
          expect(pol.MaximumRetryCount).to be < 6
        end
      end
    end
  end
end
