control 'VCFA-9X-000322' do
  title 'The VMware Cloud Foundation vCenter Server must disable SNMPv1/2 receivers.'
  desc  'SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy. Previous versions of the protocol contained well-known security weaknesses that were easily exploited. Therefore, SNMPv1/2 receivers must be disabled, while SNMPv3 is configured in another control. vCenter exposes SNMP v1/2 in the UI and SNMPv3 in the CLI.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> General.

    Click \"Edit\".

    On the \"SNMP receivers\" tab, note the presence of any enabled receiver.

    If there are any enabled receivers, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> General.

    Click \"Edit\".

    On the \"SNMP receivers\" tab, ensure all receivers are disabled.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000575'
  tag gid: 'V-VCFA-9X-000322'
  tag rid: 'SV-VCFA-9X-000322'
  tag stig_id: 'VCFA-9X-000322'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']

  command = "(Get-View -Id 'OptionManager-VpxSettings').setting | Where-Object {$_.key -like 'snmp.receiver*enabled'} | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue"
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    resultjson = json(content: result)
    resultjson.each do |snmp|
      describe "SNMP V2 Receiver: #{snmp['Key']}" do
        subject { snmp['Value'] }
        it { should cmp 'false' }
      end
    end
  end
end
