control 'DKER-CE-000049' do
  title 'Docker CE network ports on all running containers must be limited to what is needed.'
  desc  'A container can be run just with the ports defined in the Dockerfile for its image or can be arbitrarily passed run time parameters to open a list of ports. Additionally, over time, Dockerfiles may undergo various changes and the list of exposed ports may or may not be relevant to the application running within the container. Opening unneeded ports increases the attack surface of the container and the containerized application. Per the requirements set forth by the System Security Plan (SSP), ensure only needed ports are open on all running containers.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    $ docker ps --quiet | xargs docker inspect --format 'Container ID: {{ .Config.Hostname }}  IP/Ports: {{ range $v:=.NetworkSettings.Ports }}{{ range $h, $v }}{{ $h }}{{ end }}{{ end }}'

    Example result:

    Container ID: 65334557b956  IP/Ports: {0.0.0.0 49157}{:: 49157}{0.0.0.0 49156}{:: 49156}
    Container ID: 123afcc716df  IP/Ports: {0.0.0.0 8001}{:: 8001}
    Container ID: 7044965ac14c  IP/Ports: {0.0.0.0 8000}{:: 8000}

    Review the list and ensure that the ports mapped are the ones required for the containers.

    If ports are not documented and approved, this is a finding.
  "
  desc 'fix', "
    Update Dockerfiles and set or remove any EXPOSE lines accordingly.

    To ignore exposed ports as defined by a Dockerfile during container start, do not pass the \"-P/--publish-all\" flag to the Docker commands.

    When publishing needed ports at container start, use the \"-p/--publish\" flag to explicitly define the ports that are needed.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-CTR-000325'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000049'
  tag fix_id: nil
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  if !docker.containers.running?.ids.empty?
    docker.containers.running?.ids.each do |id|
      v = docker.object(id).NetworkSettings.Ports
      if v.empty?
        describe 'No ports found' do
          skip "Container: #{id} --> No ports found"
        end
      else
        v.each do |key, val|
          if val.nil? || val.empty?
            describe 'Manual Port Check' do
              skip "Container: #{id} --> Port #{key} not mapped to host port, manually analyze against the list of allowed ports"
            end
          else
            val.each do |hpval|
              v = hpval.HostPort.to_i
              describe 'Manual Port Check' do
                skip "Container: #{id} --> Port #{key} on container and port #{v} on Host, manually analyze against the list of allowed ports"
              end
            end
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
