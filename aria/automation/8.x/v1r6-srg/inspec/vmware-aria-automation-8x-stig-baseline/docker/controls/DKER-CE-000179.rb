control 'DKER-CE-000179' do
  title 'Docker CE must not mount the daemon socket inside containers.'
  desc  'If the docker socket is mounted inside a container it would allow processes running within the container to execute docker commands which effectively allows for full control of the host.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}' | grep docker.sock

    If the command produces any output, this is a finding.
  "
  desc  'fix', "
    For containers returned by the check command do the following:

    Stop the container and then start the container without specifying the volume that was mounted for docker.sock.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000243-CTR-000595'
  tag gid: 'V-DKER-CE-000179'
  tag rid: 'SV-DKER-CE-000179'
  tag stig_id: 'DKER-CE-000179'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  docker.containers.running?.ids.each do |id|
    docker.object(id).Mounts.each do |mnt|
      describe mnt.Source do
        it "Container: #{id} --> Docker socket must not be mounted to container" do
          expect(subject).not_to include 'docker.sock'
        end
      end
    end
  end
end
