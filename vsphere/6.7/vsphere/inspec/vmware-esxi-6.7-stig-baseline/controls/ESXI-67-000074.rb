control 'ESXI-67-000074' do
  title 'The ESXi host must exclusively enable TLS 1.2 for all endpoints.'
  desc  "TLS 1.0 and 1.1 are deprecated protocols with well-published
shortcomings and vulnerabilities. TLS 1.2 should be enabled on all interfaces
and SSLv3, TL 1.1, and 1.0 disabled where supported.

    Mandating TLS 1.2 may break third-party integrations and add-ons to
vSphere. Test these integrations carefully after implementing TLS 1.2 and roll
back where appropriate.

    On interfaces where required functionality is broken with TLS 1.2 this
finding is not applicable until the third-party software supports TLS 1.2.

    Be sure to modify TLS settings in the following order:

    1. Platform Services Controllers (if applicable)
    2. vCenter
    3. ESXi
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Web Client, select the host and click Configure >> System
>> Advanced System Settings.

    Find the \"UserVars.ESXiVPsDisabledProtocols\" value and verify that it is
set to the following:

    tlsv1,tlsv1.1,sslv3

    If the value is not set as above or it does not exist, this is a finding.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols

    If the value returned is not \"tlsv1,tlsv1.1,sslv3\" or the setting does
not exist, this is a finding.
  "
  desc 'fix', "
    From the vSphere Web Client, select the host and click Configure >> System
>> Advanced System Settings.

    Find the \"UserVars.ESXiVPsDisabledProtocols\" value and set it to the
following:

    tlsv1,tlsv1.1,sslv3

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols |
Set-AdvancedSetting -Value \"tlsv1,tlsv1.1,sslv3\"

    A host reboot is required for changes to take effect.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239326'
  tag rid: 'SV-239326r674907_rule'
  tag stig_id: 'ESXI-67-000074'
  tag fix_id: 'F-42518r674906_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Select-Object -ExpandProperty Value"

  describe.one do
    describe powercli_command(command) do
      its('stdout.strip') { should cmp 'tlsv1,tlsv1.1,sslv3' }
    end

    describe powercli_command(command) do
      its('stdout.strip') { should cmp 'sslv3,tlsv1,tlsv1.1' }
    end
  end
end
