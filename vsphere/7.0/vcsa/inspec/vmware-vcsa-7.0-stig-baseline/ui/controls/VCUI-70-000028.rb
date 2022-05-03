control 'VCUI-70-000028' do
  title 'vSphere UI must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the web server.'
  desc  "In order to make certain that the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism needs to be able to allocate log record storage capacity. vSphere UI configures log sizes and roation appropriately as part of it's installation routine. Verifying that the logging configuration file (serviceability.xml) has not been modified is sufficient to determine if the logging configuration has been modified from the default."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V vsphere-ui|grep serviceability.xml|grep \"^..5......\"

    If the command returns any output, this is a finding.
  "
  desc 'fix', "
    Reinstall the VCSA or roll back to a snapshot.

    Modifying the vSphere UI installation files manually is not supported by VMware.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000028'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe command('rpm -V vsphere-ui|grep serviceability.xml|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
