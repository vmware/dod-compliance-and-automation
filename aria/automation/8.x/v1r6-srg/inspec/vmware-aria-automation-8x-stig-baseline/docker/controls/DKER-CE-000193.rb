control 'DKER-CE-000193' do
  title 'Docker CE must not expose host devices to containers.'
  desc  'Host devices must not be exposed directly to a container as this could lead to elevated privileges for a container which could then be used as a pivot point to impact the system or gain access where unintended.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Devices={{ .HostConfig.Devices }}'|grep -v -E \"Devices=\\[\\]|Devices=<no value>\"

    If any containers are returned, this is a finding.
  "
  desc  'fix', "
    For containers returned by the check command do the following:

    Stop the container and then start the container without specifying the --device argument.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-DKER-CE-000193'
  tag rid: 'SV-DKER-CE-000193'
  tag stig_id: 'DKER-CE-000193'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  docker.containers.running?.ids.each do |id|
    describe docker.object(id).HostConfig.Devices do
      it "Container: #{id} --> Docker CE must not expose host devices to containers" do
        expect(subject).to eq([]).or eq(nil).or eq('Devices=<no value>')
      end
    end
  end
end
