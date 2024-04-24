control 'DKER-CE-000043' do
  title 'Docker CE must verify docker.sock permissions.'
  desc  "
    Docker daemon runs as root. The default UNIX socket hence must be owned by root. If any other user or process owns this socket, then it might be possible for that non-privileged user or process to interact with Docker daemon. Also, such a non-privileged user or process might interact with containers. This is neither secure nor desired behavior.

    Additionally, the Docker installer creates a UNIX group called docker. Users can be added to this group, and then those users would be able to read and write to default Docker UNIX socket. The membership to the docker group is tightly controlled by the system administrator. If any other group owns this socket, then it might be possible for members of that group to interact with Docker daemon. Also, such a group might not be as tightly controlled as the docker group. This is neither secure nor desired behavior.

    Hence, the default Docker UNIX socket file must be owned by root and group-owned by docker to maintain the integrity of the socket file.

    By default, the ownership and group-ownership for Docker socket file is correctly set to root:docker.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c %a:%U:%G /var/run/docker.sock

    Expected result:

    660:root:docker

    If the output from the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # chmod 660 /var/run/docker.sock
    # chown root:docker /var/run/docker.sock
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000295'
  tag gid: 'V-DKER-CE-000043'
  tag rid: 'SV-DKER-CE-000043'
  tag stig_id: 'DKER-CE-000043'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  describe file('/var/run/docker.sock') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'docker' }
    it { should_not be_more_permissive_than('0660') }
  end
end
