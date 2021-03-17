# encoding: UTF-8

control 'ESXI-70-000096' do
  title "The ESXi host must enforce the exclusive running of executables from
approved VIBs."
  desc  "The \"execInstalledOnly\" advanced ESXi boot option, when set to TRUE,
guarantees that the VMkernel executes only those binaries that have been
packaged as part of a signed VIB. While this option is effective on its own, it
can be further enhanced by telling the Secure Boot to check with the TPM to
make sure that the boot process does not proceed unless this setting is
enabled. This further protects against malicious offline changes to ESXi
configuration to disable the \"execInstalledOnly\" option.

    Note: This setting is only available in 7.0 Update 2 and later.
  "
  desc  'rationale', ''
  desc  'check', "
    If the ESXi host does not have a compatible TPM, this finding is downgraded
to a CAT III.

    From an ESXi shell, run the following command(s):

    # esxcli system settings encryption get|grep \"VIBs\"

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    $esxcli = Get-EsxCli -v2
    $esxcli.system.settings.encryption.get.invoke() | Select
RequireExecutablesOnlyFromInstalledVIBs

    Expected result:

    Require Executables Only From Installed VIBs: true

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Note: Secure Boot enforcement must be configured before this feature can be
enabled. This is covered in another control.

    From an ESXi shell, run the following command(s):

    # esxcli system settings encryption set --require-exec-installed-only=true

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
    $arguments.requireexecinstalledonly = $true
    $esxcli.system.settings.encryption.set.Invoke($arguments)

    Evacuate the host and gracefully reboot for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000096'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  if "#{input('tpmEnabled')}" == "true" 
    command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.encryption.get.invoke() | Select-Object -ExpandProperty RequireExecutablesOnlyFromInstalledVIBs"
    describe powercli_command(command) do
      its ('stdout.strip') { should cmp "true" }
    end
  end

end

