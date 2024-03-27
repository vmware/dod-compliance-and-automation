control 'VCUI-80-000013' do
  title 'The vCenter UI service must initiate session logging upon startup.'
  desc 'Logging must be started as soon as possible when a service starts and as late as possible when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicious activity to go unlogged.'
  desc 'check', 'At the command prompt, run the following command:

# grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json

Expected output:

"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/vsphere-ui/logs/vsphere-ui-runtime.log",

If no log file is specified for the "StreamRedirectFile" setting, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json

Below the last line of the "PreStartCommandArg" block, add the following line:

"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/vsphere-ui/logs/vsphere-ui-runtime.log",

Restart the service with the following command:

# vmon-cli --restart vsphere-ui'
  impact 0.5
  tag check_id: 'C-62846r935220_chk'
  tag severity: 'medium'
  tag gid: 'V-259106'
  tag rid: 'SV-259106r935222_rule'
  tag stig_id: 'VCUI-80-000013'
  tag gtitle: 'SRG-APP-000092-AS-000053'
  tag fix_id: 'F-62755r935221_fix'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  describe json("#{input('svcJsonPath')}") do
    its('StreamRedirectFile') { should eq "#{input('streamRedirectFile')}" }
  end
end
