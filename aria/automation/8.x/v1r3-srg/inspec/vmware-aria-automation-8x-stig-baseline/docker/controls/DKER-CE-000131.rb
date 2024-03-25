control 'DKER-CE-000131' do
  title 'Docker CE must not allow host user namespaces to be shared.'
  desc  'User namespaces ensure that a root process inside the container will be mapped to a non-root process outside the container. Sharing the user namespaces of the host with the container does not adequately isolate containers from the host and could allow an attacker to break out of a compromised container.'
  desc  'rationale', ''
  desc  'check', "
    From the command line interface, run the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UsernsMode={{ .HostConfig.UsernsMode }}'|grep -v \"UsernsMode=\"

    If the command produces any output, this is a finding.
  "
  desc 'fix', 'For any containers flagged by the check stop them and run them without the "--userns=host" flag.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000431-CTR-001065'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000131'
  tag fix_id: nil
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']

  if !docker.containers.running?.ids.empty?
    docker.containers.running?.ids.each do |id|
      describe docker.object(id).HostConfig.UsernsMode do
        it "Container: #{id} --> Docker CE must not allow host user namespaces to be shared" do
          expect(subject).to eq('')
        end
      end
    end
  else
    describe 'No containers found' do
      skip 'No containers found...skipping tests'
    end
  end
end
