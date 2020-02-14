control "VCPF-67-000006" do
  title "Performance Charts must generate log records for system startup and
shutdown."
  desc  "Logging must be started as soon as possible when a service starts and
when a service is stopped. Many forms of suspicious actions can be detected by
analyzing logs for unexpected service starts and stops. Also, by starting to
log immediately after a service starts, it becomes more difficult for suspicous
activity to go un-logged.

    On the VCSA, the vmware-vmon service starts up the JVMs for various vCenter
processes, including Performance Charts, and the individual json config files
control the early jvm logging. Ensuring these json files are configured
correctly enables early java stdout and stderr logging."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000089-WSR-000047"
  tag gid: nil
  tag rid: "VCPF-67-000006"
  tag stig_id: "VCPF-67-000006"
  tag cci: "CCI-000169"
  tag nist: ["AU-12 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/perfcharts.json

Expected result:

\"StreamRedirectFile\" :
\"%VMWARE_LOG_DIR%/vmware/perfcharts/vmware-perfcharts-runtime.log\",

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/etc/vmware/vmware-vmon/svcCfgfiles/perfcharts.json . Below the last line of
the 'PreStartCommandArg' block add the following line:

\"StreamRedirectFile\" :
\"%VMWARE_LOG_DIR%/vmware/perfcharts/vmware-perfcharts-runtime.log\",

Restart the appliance for changes to take effect."

  describe json('/etc/vmware/vmware-vmon/svcCfgfiles/perfcharts.json') do
    its('StreamRedirectFile') { should eq '%VMWARE_LOG_DIR%/vmware/perfcharts/vmware-perfcharts-runtime.log'}
  end

end

