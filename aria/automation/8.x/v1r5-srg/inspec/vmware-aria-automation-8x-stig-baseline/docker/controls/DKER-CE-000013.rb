control 'DKER-CE-000013' do
  title 'Docker CE must not share its host process namespace with containers.'
  desc  "
    Process ID (PID) namespaces isolate the PID number space, meaning that processes in different PID namespaces can have the same PID. This is process level isolation between containers and the host.

    PID namespace provides separation of processes. The PID Namespace removes the view of the system processes, and allows process IDs to be reused including PID 1. If the host's PID namespace is shared with the container, it would allow processes within the container to see all of the processes on the host system. This breaks the benefit of process level isolation between the host and the containers. Someone having access to the container can eventually know all the processes running on the host system and can even kill the host system processes from within the container. Hence, do not share the host's process namespace with the containers.

    Container processes cannot see the processes on the host system. In certain cases, the container could share the host's process namespace. For example, the user could build a container with debugging tools like strace or gdb, but want to use these tools when debugging processes within the container. If this is desired, then share only one (or needed) host process by using the -p switch.

    Example:
    docker run --pid=host rhel7 strace -p 1234

    By default, all containers have the PID namespace enabled and the host's process namespace is not shared with the containers.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: PidMode={{ .HostConfig.PidMode }}' | grep PidMode=host

    If the command produces any output, this is a finding.
  "
  desc  'fix', "
    For containers returned by the check command do the following:

    Stop the container and then start the container without specifying the --pid=host argument.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000038-CTR-000105'
  tag gid: 'V-DKER-CE-000013'
  tag rid: 'SV-DKER-CE-000013'
  tag stig_id: 'DKER-CE-000013'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
  docker.containers.running?.ids.each do |id|
    describe docker.object(id).HostConfig.PidMode do
      it "Container: #{id} --> Host process must not be shared with container" do
        expect(subject).not_to eq('host')
      end
    end
  end
end
