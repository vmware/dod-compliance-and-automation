control 'VCEM-70-000006' do
  title 'ESX Agent Manager must generate log records for system startup and shutdown.'
  desc 'Logging must be started as soon as possible when a service starts and as late as possible when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicious activity to go unlogged.'
  desc 'check', 'At the command prompt, run the following command:

# grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/eam.json

Expected output:

"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/eam/jvm.log",

If no log file is specified for the "StreamRedirectFile" setting, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware/vmware-vmon/svcCfgfiles/eam.json

Below the last line of the "PreStartCommandArg" block, add the following line:

"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/eam/jvm.log",

Restart the appliance for changes to take effect.'
  impact 0.5
  tag check_id: 'C-60353r888588_chk'
  tag severity: 'medium'
  tag gid: 'V-256678'
  tag rid: 'SV-256678r888590_rule'
  tag stig_id: 'VCEM-70-000006'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-60296r888589_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  describe json("#{input('svcJsonPath')}") do
    its('StreamRedirectFile') { should eq "#{input('streamRedirectFile')}" }
  end
end
