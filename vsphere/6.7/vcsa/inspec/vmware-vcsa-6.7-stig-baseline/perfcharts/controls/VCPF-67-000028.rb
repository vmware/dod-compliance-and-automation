control 'VCPF-67-000028' do
  title 'Performance Charts must be configured with the appropriate ports.'
  desc  "Web servers provide numerous processes, features, and functionalities
that use TCP/IP ports. Some of these processes may be deemed unnecessary or too
unsecure to run on a production system. The ports that the Performance Charts
listens on are configured in the \"catalina.properties\" file and must be
verified as accurate to their shipping state."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep '^bio\\.'
/usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties

    Expected result:

    bio.http.port=13080
    bio.https.port=8443

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Navigate to and open
/usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties.

    Navigate to the ports specification section.

    Add or modify the following lines:

    bio.http.port=13080
    bio.https.port=8443
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag gid: 'V-239429'
  tag rid: 'SV-239429r816592_rule'
  tag stig_id: 'VCPF-67-000028'
  tag fix_id: 'F-42621r816591_fix'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio.http.port'] do
    it { should eq "#{input('httpPort')}" }
  end

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio.https.port'] do
    it { should eq "#{input('httpsPort')}" }
  end
end
