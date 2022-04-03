control 'VCEM-67-000006' do
  title "ESX Agent Manager must generate log records for system startup and
shutdown."
  desc  "Logging must be started as soon as possible when a service starts and
as late as possible when a service is stopped. Many forms of suspicious actions
can be detected by analyzing logs for unexpected service starts and stops.
Also, by starting to log immediately after a service starts, it becomes more
difficult for suspicious activity to go unlogged."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/eam.json

    Expected output:

    \"StreamRedirectFile\" : \"%VMWARE_LOG_DIR%/vmware/eam/jvm.log\",

    If no log file is specified for the \"StreamRedirectFile\" setting, this is
a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware/vmware-vmon/svcCfgfiles/eam.json

    Below the last line of the \"PreStartCommandArg\" block, add the following
line:

    \"StreamRedirectFile\" : \"%VMWARE_LOG_DIR%/vmware/eam/jvm.log\",

    Restart the appliance for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag gid: 'V-239377'
  tag rid: 'SV-239377r674625_rule'
  tag stig_id: 'VCEM-67-000006'
  tag fix_id: 'F-42569r674624_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  describe json("#{input('svcJsonPath')}") do
    its('StreamRedirectFile') { should eq "#{input('streamRedirectFile')}" }
  end
end
