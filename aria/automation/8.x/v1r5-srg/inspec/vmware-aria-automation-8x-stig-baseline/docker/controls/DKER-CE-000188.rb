control 'DKER-CE-000188' do
  title 'Docker CE must not disable the default seccomp profile.'
  desc  "
    Seccomp filtering provides a means for a process to specify a filter for incoming system calls. The default Docker seccomp profile works on a whitelist basis and allows 311 system calls, blocking all others. It must not be disabled unless it hinders the container application usage.

    A large number of system calls are exposed to every userland process with many of them going unused for the entire lifetime of the process. Most of the applications do not need all the system calls and thus benefit by having a reduced set of available system calls. The reduced set of system calls reduces the total kernel surface exposed to the application and thus improves application security.

    The default seccomp profile blocks syscalls, regardless of --cap-add passed to the container. Create a custom seccomp profile in such cases. Disable the default seccomp profile by passing --security-opt=seccomp:unconfined on docker run.

    When running a container, it uses the default profile unless it is overridden with the --security-opt option.
  "
  desc  'rationale', ''
  desc  'check', "
    The Docker daemon is configured with a seccomp profile by default but this can be overwritten at the time of container execution so both must be verified.

    To verify the Docker daemon is configured with the default seccomp profile, execute the following command:

    # docker info --format '{{ .SecurityOptions }}'

    Example output:

    [name=apparmor name=seccomp,profile=default]

    If the command output does not contain \"name=seccomp,profile=default\", this is a finding.

    To verify containers are not configured to overwrite the default seccomp profile, execute the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}' | grep seccomp

    If any containers are returned and have specified \"seccomp=unconfined\", this is a finding.
  "
  desc 'fix', "
    To configure the default seccomp profile in the daemon.json configuration file, do the following:

    Navigate to and open:

    /etc/docker/daemon.json

    Remove the \"seccomp-profile\" option.

    Note: This may also be specified as an argument to the Docker daemon service and must be removed there if specified in that manner.

    Restart the docker daemon by running the following command:

    # systemctl restart docker.service

    For containers returned by the check command do the following:

    Stop the container and then start the container without specifying the --security-opt seccomp=unconfined argument.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-DKER-CE-000188'
  tag rid: 'SV-DKER-CE-000188'
  tag stig_id: 'DKER-CE-000188'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  describe docker.info.SecurityOptions do
    it 'The default seccomp profile must be enabled' do
      expect(subject).to include('name=seccomp,profile=default')
    end
  end
end
