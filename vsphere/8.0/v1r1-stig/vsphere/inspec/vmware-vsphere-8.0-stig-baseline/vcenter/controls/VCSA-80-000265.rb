control 'VCSA-80-000265' do
  title 'The vCenter server must disable SNMPv1/2 receivers.'
  desc 'SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy. Previous versions of the protocol contained well-known security weaknesses that were easily exploited. Therefore, SNMPv1/2 receivers must be disabled, while SNMPv3 is configured in another control. vCenter exposes SNMP v1/2 in the UI and SNMPv3 in the CLI.'
  desc 'check', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Settings >> General.

Click "Edit".

On the "SNMP receivers" tab, note the presence of any enabled receiver.

If there are any enabled receivers, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Settings >> General.

Click "Edit".

On the "SNMP receivers" tab, ensure all receivers are disabled.'
  impact 0.5
  tag check_id: 'C-62672r934452_chk'
  tag severity: 'medium'
  tag gid: 'V-258932'
  tag rid: 'SV-258932r934454_rule'
  tag stig_id: 'VCSA-80-000265'
  tag gtitle: 'SRG-APP-000575'
  tag fix_id: 'F-62581r934453_fix'
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
