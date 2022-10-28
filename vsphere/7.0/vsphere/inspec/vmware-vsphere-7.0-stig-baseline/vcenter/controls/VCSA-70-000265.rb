control 'VCSA-70-000265' do
  title 'The vCenter server must disable SNMPv1/2 receivers.'
  desc  'SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy while previous versions of the protocol contained well-known security weaknesses that were easily exploited. As such, SNMPv1/2 receivers must be disabled while SNMPv3 is configured in another control. vCenter exposes SNMP v1/2 in the UI and SNMPv3 in the CLI.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> General.

    Click \"Edit\".

    On the \"SNMP receivers\" tab, note the presence of any enabled receiver.

    If there are any enabled receivers, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> General.

    Click \"Edit\"

     On the \"SNMP receivers\" tab, ensure all receivers are disabled.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000575'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000265'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']

  command = "(Get-View -Id 'OptionManager-VpxSettings').setting | Where-Object {$_.key -match 'snmp.receiver.1.enabled'} | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'False' }
  end
  command = "(Get-View -Id 'OptionManager-VpxSettings').setting | Where-Object {$_.key -match 'snmp.receiver.2.enabled'} | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'False' }
  end
  command = "(Get-View -Id 'OptionManager-VpxSettings').setting | Where-Object {$_.key -match 'snmp.receiver.3.enabled'} | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'False' }
  end
  command = "(Get-View -Id 'OptionManager-VpxSettings').setting | Where-Object {$_.key -match 'snmp.receiver.4.enabled'} | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'False' }
  end
end
