control 'DKER-CE-000050' do
  title 'Docker CE host privileged ports must not be mapped within containers.'
  desc  'Privileged ports are those ports below 1024 and that require system privileges for their use. If containers are able to use these ports, the container must be run as a privileged user. The container platform must stop containers that try to map to these ports directly. Allowing non-privileged ports to be mapped to the container-privileged port is the allowable method when a certain port is needed. An example is mapping port 8080 externally to port 80 in the container.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    $ docker ps --quiet | xargs docker inspect --format 'Container ID: {{ .Config.Hostname }}  IP/Ports: {{ range $v:=.NetworkSettings.Ports }}{{ range $h, $v }}{{ $h }}{{ end }}{{ end }}'

    Example result:

    Container ID: 65334557b956  IP/Ports: {0.0.0.0 49157}{:: 49157}{0.0.0.0 49156}{:: 49156}
    Container ID: 123afcc716df  IP/Ports: {0.0.0.0 8001}{:: 8001}
    Container ID: 7044965ac14c  IP/Ports: {0.0.0.0 8000}{:: 8000}

    If any of the host ports returned are 1024 or below, this is a finding.
  "
  desc 'fix', 'Reconfigure and restart any containers using privileged ports to utilize non-privileged ports.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-CTR-000330'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000050'
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
        docker.object(id).NetworkSettings.Ports.each_value do |portval|
          if portval.nil?
            describe 'Null Port' do
              skip "Container: #{id} --> Port not mapped to host port"
            end
          else
            portval.each do |hpval|
              i = hpval.HostIp
              v = hpval.HostPort.to_i
              describe v do
                it "Container: #{id} --> Port #{v} must be greater than 1024 (Host IP: #{i})" do
                  expect(v).to be > 1024
                end
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
