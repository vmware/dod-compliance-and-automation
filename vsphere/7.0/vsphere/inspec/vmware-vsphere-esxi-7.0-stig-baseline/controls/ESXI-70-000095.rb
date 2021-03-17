# encoding: UTF-8

control 'ESXI-70-000095' do
  title 'The ESXi host must implement Secure Boot enforcement.'
  desc  "Secure Boot is part of the UEFI firmware standard. With UEFI Secure
Boot enabled, a host refuses to load any UEFI driver or app unless the
operating system bootloader has a valid digital signature. Secure Boot for ESXi
requires support from the firmware and it requires that all ESXi kernel
modules, drivers and VIBs be signed by VMware or a partner subordinate.

    Secure Boot is enabled in the BIOS of the ESXi physical server and
supported by the hypervisor boot loader. This control flips ESXi from merely
supporting Secure Boot to requiring it. Without this setting enabled, and
configuration encryption, an ESXi host could be subject to offline attacks. An
attacker could simply transfer the ESXi install drive to a non-Secure Boot host
and boot it up without ESXi complaining.

    Note: This setting is only available in 7.0 Update 2 and later.
  "
  desc  'rationale', ''
  desc  'check', "
    If the ESXi host does not have a compatible TPM, this finding is downgraded
to a CAT III.

    From an ESXi shell, run the following command(s):

    # esxcli system settings encryption get|grep \"Secure Boot\"

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    $esxcli = Get-EsxCli -v2
    $esxcli.system.settings.encryption.get.invoke() | Select RequireSecureBoot

    Expected result:

    Require Secure Boot: true

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    This setting cannot be configured until Secure Boot is properly enabled in
the BIOS.

    From an ESXi shell, run the following command(s):

    # esxcli system settings encryption set --require-secure-boot=true

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
    $arguments.requiresecureboot = $true
    $esxcli.system.settings.encryption.set.Invoke($arguments)

    Evacuate the host and gracefully reboot for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000095'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  if "#{input('tpmEnabled')}" == "true" 
    command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.encryption.get.invoke() | Select-Object -ExpandProperty RequireSecureBoot"
    describe powercli_command(command) do
      its ('stdout.strip') { should cmp "true" }
    end
  end

end

