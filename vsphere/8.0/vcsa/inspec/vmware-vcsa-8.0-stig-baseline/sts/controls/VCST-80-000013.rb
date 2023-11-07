control 'VCST-80-000013' do
  title 'The vCenter STS service must initiate session logging upon startup.'
  desc 'Logging must be started as soon as possible when a service starts and as late as possible when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicious activity to go unlogged.'
  desc 'check', 'At the command prompt, run the following command:

# grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/sts-lin.json

Expected output:

"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/sso/sts-runtime.log",

If no log file is specified for the "StreamRedirectFile" setting, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware/vmware-vmon/svcCfgfiles/sts-lin.json

Below the last line of the "PreStartCommandArg" block, add the following line:

"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/sso/sts-runtime.log",

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-62713r934575_chk'
  tag severity: 'medium'
  tag gid: 'V-258973'
  tag rid: 'SV-258973r934577_rule'
  tag stig_id: 'VCST-80-000013'
  tag gtitle: 'SRG-APP-000092-AS-000053'
  tag fix_id: 'F-62622r934576_fix'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  describe json("#{input('svcJsonPath')}") do
    its('StreamRedirectFile') { should eq "#{input('streamRedirectFile')}" }
  end
end
