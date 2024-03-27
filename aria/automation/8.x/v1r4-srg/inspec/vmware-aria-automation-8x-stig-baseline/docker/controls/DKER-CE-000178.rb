control 'DKER-CE-000178' do
  title 'Docker CE must verify containerd.sock permissions.'
  desc  'Containerd is an underlying component used by Docker to create and manage containers. It provides a socket file similar to the Docker socket, which must be protected from unauthorized access. If any other user or process owns this socket, it might be possible for that non-privileged user or process to interact with the Containerd daemon. Additionally, in this case a non-privileged user or process might be able to interact with containers which is neither a secure nor desired behavior.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c %a:%U:%G /run/containerd/containerd.sock

    Expected result:

    660:root:root

    If the output from the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # chmod 660 /run/containerd/containerd.sock
    # chown root:root /run/containerd/containerd.sock
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000295'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000178'
  tag fix_id: nil
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe file('/run/containerd/containerd.sock') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0660') }
  end
end
