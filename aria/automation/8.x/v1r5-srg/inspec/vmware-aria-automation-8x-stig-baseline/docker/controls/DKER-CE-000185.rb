control 'DKER-CE-000185' do
  title 'Docker CE must not overwrite the default ulimit.'
  desc  "
    The default ulimit is set at the Docker daemon level. However, override the default ulimit setting, if needed, during container runtime.

    ulimit provides control over the resources available to the shell and to processes started by it. Setting system resource limits judiciously prevents many disasters such as a fork bomb. Sometimes, even friendly users and legitimate processes can overuse system resources and in-turn can make the system unusable.

    The default ulimit set at the Docker daemon level must be honored. If the default ulimit settings are not appropriate for a particular container instance, override them as an exception. But, do not make this a practice. If most of the container instances are overriding default ulimit settings, consider changing the default ulimit settings to something that is appropriate for your needs.

    If the ulimits are not set properly, the desired resource control might not be achieved and might even make the system unusable.

    Container instances inherit the default ulimit settings set at the Docker daemon level.
  "
  desc  'rationale', ''
  desc  'check', "
    To verify containers are not configured to overwrite the default ulimit, execute the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Ulimits={{ .HostConfig.Ulimits }}'|grep -v \"Ulimits=<no value>\"

    If any containers are returned, this is a finding.

    If a container sets a Ulimit and the setting is not approved in the SSP, this is a finding.
  "
  desc  'fix', "
    For containers returned by the check command do the following:

    Stop the container and then start the container without specifying the --ulimit argument.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-DKER-CE-000185'
  tag rid: 'SV-DKER-CE-000185'
  tag stig_id: 'DKER-CE-000185'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  docker.containers.running?.ids.each do |id|
    describe 'Checking for null ulimit value' do
      it "Container: #{id} --> Docker container must not override the default ulimit value" do
        expect(docker.object(id).HostConfig.Ulimits).to be nil
      end
    end
  end
end
