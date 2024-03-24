control 'DKER-CE-000192' do
  title 'Docker CE must not allow container mounts to be shared.'
  desc  "Mount propagation mode allows mounting volumes in shared, slave or private mode on a container. Do not use shared mount propagation mode until needed.

    A shared mount is replicated at all mounts and the changes made at any mount point are propagated to all mounts. Mounting a volume in shared mode does not restrict any other container from mounting and making changes to that volume. These unintended volume changes could potentially impact data hosted on the mounted volume. Do not set mount propagation mode to shared until needed.

    By default, the container mounts are private.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}:Propagation={{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}' | grep shared

    If any containers are returned, this is a finding.
  "
  desc 'fix', "
    For containers returned by the check command do the following:

    Stop the container and then start the container by updating the mount propagation arguments to be private instead of shared.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000192'
  tag fix_id: nil
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if !docker.containers.running?.ids.empty?
    docker.containers.running?.ids.each do |id|
      docker.object(id).Mounts.each do |mnt|
        i = mnt.Propagation
        describe i do
          it "Container: #{id} --> Mount must not be shared" do
            expect(i).not_to cmp 'shared'
          end
        end
      end
    end
  else
    describe 'No Containers Found' do
      skip 'No Containers Found...skipping tests'
    end
  end
end
