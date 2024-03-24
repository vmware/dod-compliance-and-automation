control 'DKER-CE-000174' do
  title 'Docker CE must not share its host IPC namespace with containers.'
  desc  "IPC (POSIX/SysV IPC) namespace provides separation of named shared memory segments, semaphores, and message queues. IPC namespace on the host thus must not be shared with the containers and must remain isolated.

    IPC namespace provides separation of IPC between the host and containers. If the host's IPC namespace is shared with the container, it would allow processes within the container to see all of the IPC on the host system. This breaks the benefit of IPC level isolation between the host and the containers. Someone having access to the container could eventually manipulate the host IPC. Hence, do not share the host's IPC namespace with the containers.

    Shared memory segments are used to accelerate inter-process communication. It is commonly used by high-performance applications. If such applications are containerized into multiple containers, the user might need to share the IPC namespace of the containers to achieve high performance. In such cases, the user must still be sharing container specific IPC namespaces only and not the host IPC namespace. The user may share the container's IPC namespace with another container as below:

    Example:
    docker run --interactive --tty --ipc=container:e3a7a1a97c58 centos /bin/bash

    By default, all containers have the IPC namespace enabled and host IPC namespace is not shared with any container.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: IpcMode={{ .HostConfig.IpcMode }}' | grep IpcMode=host

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    For containers returned by the check command do the following:

    Stop the container and then start the container without specifying the --IpcMode=host argument.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000038-CTR-000105'
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']

  if !docker.containers.running?.ids.empty?
    docker.containers.running?.ids.each do |id|
      describe docker.object(id).HostConfig.IpcMode do
        it "Container: #{id} --> Host IPC namespace must not be shared with container" do
          expect(subject).not_to eq('host')
        end
      end
    end
  else
    describe 'No Containers Found' do
      skip 'No Containers Found...skipping tests'
    end
  end
end
