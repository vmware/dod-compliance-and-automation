control 'DKER-CE-000047' do
  title 'Docker CE must disable experimental features.'
  desc  'Enabling experimental features in the docker daemon may introduce vulnerabilities through unmaintained or non-production ready features that have not gone through the rigor of production features.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker version --format '{{ .Server.Experimental }}'

    Expected result:

    false

    If the output from the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    To disable experimental features, do the following:

    Navigate to and open:

    /etc/docker/daemon.json

    Add or update the option as seen in the example below:

      \"experimental\": \"false\"

    Restart the docker daemon by running the following command:

    # systemctl restart docker.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-CTR-000315'
  tag gid: 'V-DKER-CE-000047'
  tag rid: 'SV-DKER-CE-000047'
  tag stig_id: 'DKER-CE-000047'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  describe (docker.version.Server.Components.find { |item| item.Name == 'Engine' }).Details.Experimental do
    it { should cmp 'false' }
  end
end
