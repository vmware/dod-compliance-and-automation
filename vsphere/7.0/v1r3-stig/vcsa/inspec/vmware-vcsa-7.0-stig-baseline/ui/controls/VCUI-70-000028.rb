control 'VCUI-70-000028' do
  title 'vSphere UI must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the web server.'
  desc 'To ensure the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism must be able to allocate log record storage capacity. vSphere UI configures log sizes and rotation appropriately as part of its installation routine. Verifying that the logging configuration file ("serviceability.xml") has not been modified is sufficient to determine if the logging configuration has been modified from the default.'
  desc 'check', 'At the command prompt, run the following command:

# rpm -V vsphere-ui|grep serviceability.xml|grep "^..5......"

If the command returns any output, this is a finding.'
  desc 'fix', 'Reinstall the VCSA or roll back to a snapshot.

VMware does not support modifying the vSphere UI installation files manually.'
  impact 0.5
  tag check_id: 'C-60480r889412_chk'
  tag severity: 'medium'
  tag gid: 'V-256805'
  tag rid: 'SV-256805r889414_rule'
  tag stig_id: 'VCUI-70-000028'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag fix_id: 'F-60423r889413_fix'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe command('rpm -V vsphere-ui|grep serviceability.xml|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
