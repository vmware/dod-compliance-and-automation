control 'DKER-CE-000184' do
  title 'Docker CE must not use the aufs storage driver.'
  desc  "The aufs storage driver is based on an older Linux kernel patch set that is known to cause kernel crashes.

    This storage driver also allows containers to share executable and shared library memory.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker info --format 'Storage Driver: {{ .Driver }}'

    Expected result:

    Storage Driver: overlay2

    If the output of the command is aufs, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/docker/daemon.json

    Find the \"storage-driver\" line and remove it.

    Restart the docker daemon by running the following command:

    # systemctl restart docker.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000184'
  tag fix_id: nil
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe docker.info.Driver do
    it 'Storage Driver must not be aufs' do
      expect(subject).not_to cmp 'aufs'
    end
  end
end
