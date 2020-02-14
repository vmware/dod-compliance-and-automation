control "VCEM-67-000006" do
  title "ESX Agent Manager must generate log records for system startup and
shutdown."
  desc  "Logging must be started as soon as possible when a service starts and
as late as possible when a service is stopped. Many forms of suspicious actions
can be detected by analyzing logs for unexpected service starts and stops.
Also, by starting to log immediately after a service starts, it becomes more
difficult for suspicous activity to go un-logged."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000089-WSR-000047"
  tag gid: nil
  tag rid: "VCEM-67-000006"
  tag stig_id: "VCEM-67-000006"
  tag cci: "CCI-000169"
  tag nist: ["AU-12 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/eam.json

Expected output:

\"StreamRedirectFile\" : \"%VMWARE_LOG_DIR%/vmware/eam/jvm.log\",

If there is no log file specified for the StreamRedirectFile setting, this is a
finding."
  desc 'fix', "Navigate to and open /etc/vmware/vmware-vmon/svcCfgfiles/eam.json .
Below the last line of the 'PreStartCommandArg' block add the following line:

\"StreamRedirectFile\" : \"%VMWARE_LOG_DIR%/vmware/eam/jvm.log\",

Restart the appliance for changes to take effect."

  describe json('/etc/vmware/vmware-vmon/svcCfgfiles/eam.json') do
    its('StreamRedirectFile') { should eq '%VMWARE_LOG_DIR%/vmware/eam/jvm.log'}
  end

end

