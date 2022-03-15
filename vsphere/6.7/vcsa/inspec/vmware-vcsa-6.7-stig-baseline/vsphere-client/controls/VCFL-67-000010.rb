control 'VCFL-67-000010' do
  title "vSphere Client must generate log records during Java startup and
shutdown."
  desc  "Logging must be started as soon as possible when a service starts and
when a service is stopped. Many forms of suspicious actions can be detected by
analyzing logs for unexpected service starts and stops. Also, by starting to
log immediately after a service starts, it becomes more difficult for
suspicious activity to go unlogged.

    On the VCSA, the vmware-vmon service starts up the JVMs for various vCenter
processes, including vSphere Client, and the individual json config files
control the early jvm logging. Ensuring these json files are configured
correctly enables early Java stdout and stderr logging.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep StreamRedirectFile
/etc/vmware/vmware-vmon/svcCfgfiles/vsphere-client.json

    Expected result:

    \"StreamRedirectFile\":
\"%VMWARE_LOG_DIR%/vmware/vsphere-client/logs/vsphere-client-runtime.log\",

    If there is no log file specified for the \"StreamRedirectFile\" setting,
this is a finding.
  "
  desc 'fix', "
    Navigate to and open
/etc/vmware/vmware-vmon/svcCfgfiles/vsphere-client.json.

    Below the last line of the \"PreStartCommandArg\" block, add the following
line:

    \"StreamRedirectFile\":
\"%VMWARE_LOG_DIR%/vmware/vsphere-client/logs/vsphere-client-runtime.log\",

    Restart the appliance for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag gid: 'V-239752'
  tag rid: 'SV-239752r679483_rule'
  tag stig_id: 'VCFL-67-000010'
  tag fix_id: 'F-42944r679482_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  describe json('/etc/vmware/vmware-vmon/svcCfgfiles/vsphere-client.json') do
    its('StreamRedirectFile') { should eq '%VMWARE_LOG_DIR%/vmware/vsphere-client/logs/vsphere-client-runtime.log' }
  end
end
