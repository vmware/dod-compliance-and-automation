control 'VCPF-70-000032' do
  title 'Performance Charts must disable the shutdown port.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a denial of service, and the second is to put in place changes the attacker made to the web server configuration.

If the Tomcat shutdown port feature is enabled, a shutdown signal can be sent to Performance Charts through this port. To ensure availability, the shutdown port must be disabled.'
  desc 'check', 'At the command prompt, run the following command:

# grep base.shutdown.port /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties

Expected result:

base.shutdown.port=-1

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-eam/catalina.properties

Navigate to the ports specification section.

Add or modify the following line:

base.shutdown.port=-1

Restart the service with the following command:

# vmon-cli --restart perfcharts'
  impact 0.5
  tag check_id: 'C-60317r888415_chk'
  tag severity: 'medium'
  tag gid: 'V-256642'
  tag rid: 'SV-256642r888417_rule'
  tag stig_id: 'VCPF-70-000032'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-60260r888416_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['base.shutdown.port'] do
    it { should eq "#{input('shutdownPort')}" }
  end
end
