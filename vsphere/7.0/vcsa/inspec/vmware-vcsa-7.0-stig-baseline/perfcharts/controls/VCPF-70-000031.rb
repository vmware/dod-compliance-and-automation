control 'VCPF-70-000031' do
  title 'Performance Charts must be configured with the appropriate ports.'
  desc 'Web servers provide numerous processes, features, and functionalities that use TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. The ports that Performance Charts listens on are configured in the "catalina.properties" file and must be verified as accurate to their shipping state.'
  desc 'check', "At the command prompt, run the following command:

# grep '^bio\\.' /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties

Expected result:

bio.http.port=13080

If the output of the command does not match the expected result, this is a finding."
  desc 'fix', 'Navigate to and open:

/etc/vmware-eam/catalina.properties

Navigate to the ports specification section.

Add or modify the following lines:

bio.http.port=13080

Restart the service with the following command:

# vmon-cli --restart perfcharts'
  impact 0.5
  tag check_id: 'C-60316r888412_chk'
  tag severity: 'medium'
  tag gid: 'V-256641'
  tag rid: 'SV-256641r888414_rule'
  tag stig_id: 'VCPF-70-000031'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-60259r888413_fix'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio.http.port'] do
    it { should eq "#{input('httpPort')}" }
  end
end
