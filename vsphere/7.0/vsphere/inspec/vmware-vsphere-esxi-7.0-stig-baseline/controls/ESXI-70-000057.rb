# encoding: UTF-8

control 'ESXI-70-000057' do
  title "The ESXi host must configure the firewall to block network traffic by
default."
  desc  "In addition to service specific firewall rules ESXi has a default
firewall rule policy to allow or deny incoming and outgoing traffic. Reduce the
risk of attack by making sure this is set to deny incoming and outgoing
traffic."
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # esxcli system snmp get

    If the \"Default Action\" does not equal \"DROP\", this is a finding.

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHostFirewallDefaultPolicy

    If the Incoming or Outgoing policies are True, this is a finding.
  "
  desc  'fix', "
    From an ESXi shell, run the following command(s):

    # esxcli network firewall set --default-action=false

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHostFirewallDefaultPolicy | Set-VMHostFirewallDefaultPolicy
-AllowIncoming $false -AllowOutgoing $false
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000057'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostFirewallDefaultPolicy"
  describe powercli_command(command) do
    its ('stdout.strip') { should_not match "True" }
  end

end

