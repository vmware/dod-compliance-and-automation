control "VCUI-67-000026" do
  title "vSphere UI must use a logging mechanism that is configured to allocate
log record storage capacity large enough to accommodate the logging
requirements of the web server."
  desc  "In order to make certain that the logging mechanism used by the web
server has sufficient storage capacity in which to write the logs, the logging
mechanism needs to be able to allocate log record storage capacity. vSphere UI
configures log sizes and roation appropriately as part of it's installation
routine. Verifying that the logging configuration file (serviceability.xml) has
not been modified is sufficient to determine if the logging configuration has
been modified from the default."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000026"
  tag stig_id: "VCUI-67-000026"
  tag cci: nil
  tag nist: nil
  desc 'check', "At the command prompt, execute the following command:

# rpm -V vsphere-ui|grep serviceability.xml|grep \"^..5......\"

If the above command returns any output, this is a finding."
  desc 'fix', "Re-install the VCSA or roll back to a snapshot. Modifying the
vSphere UI installation files manually is not supported by VMware."

  describe command('rpm -V vsphere-ui|grep serviceability.xml|grep "^..5......"') do
    its ('stdout.strip') { should eq '' }
  end

end