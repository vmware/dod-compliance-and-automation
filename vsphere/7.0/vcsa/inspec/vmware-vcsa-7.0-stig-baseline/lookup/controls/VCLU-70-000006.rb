control 'VCLU-70-000006' do
  title 'Lookup Service must generate log records for system startup and shutdown.'
  desc  "
    Logging must be started as soon as possible when a service starts and when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicous activity to go unlogged.

    On the VCSA, the \"vmware-vmon\" service starts up the JVMs for various vCenter processes, including Lookup Service, and the individual json config files control the early jvm logging. Ensuring these json files are configured correctly enables early java \"stdout\" and \"stderr\" logging.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/lookupsvc.json

    Expected result:

    \"StreamRedirectFile\": \"%VMWARE_LOG_DIR%/vmware/lookupsvc/lookupsvc_stream.log\",

    If there is no log file specified for the StreamRedirectFile setting, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware/vmware-vmon/svcCfgfiles/lookupsvc.json

    Below the last line of the \"PreStartCommandArg\" block add or re-configure the following line:

    \"StreamRedirectFile\": \"%VMWARE_LOG_DIR%/vmware/lookupsvc/lookupsvc_stream.log\",

    Restart the appliance for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag satisfies: ['SRG-APP-000092-WSR-000055']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLU-70-000006'
  tag cci: ['CCI-000169', 'CCI-001464']
  tag nist: ['AU-12 a', 'AU-14 (1)']

  describe json("#{input('svcJsonPath')}") do
    its('StreamRedirectFile') { should eq "#{input('streamRedirectFile')}" }
  end
end
