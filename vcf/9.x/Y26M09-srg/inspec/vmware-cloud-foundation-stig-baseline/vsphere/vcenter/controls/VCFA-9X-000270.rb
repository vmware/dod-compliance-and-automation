control 'VCFA-9X-000270' do
  title 'The vCenter Server must disable accounts used for Integrated Windows Authentication (IWA).'
  desc  "
    Disabling expired, inactive, or otherwise anomalous accounts supports the concepts of least privilege and least functionality which reduce the attack surface of the system.

    If not used for their intended purpose, default accounts must be disabled. vCenter ships with several default accounts, two of which are specific to IWA and SASL/Kerberos authentication. If other methods of authentication are used, these accounts are not needed and must be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    If IWA is used for vCenter authentication, this is not applicable.

    From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Users.

    Change the domain to \"vsphere.local\" and review the \"K/M\" and \"krbtgt/VSPHERE.LOCAL\" accounts.

    If the \"K/M\" and \"krbtgt/VSPHERE.LOCAL\" accounts are not disabled, this is a finding.

    Note: If an alternate SSO domain name was specified then substitute that for \"VSPHERE.LOCAL\".
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Users.

    Select the \"K/M\" or \"krbtgt/VSPHERE.LOCAL\" and click \"More\" then select \"Disable\".

    Click \"Ok\" to disable the user account.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000700'
  tag gid: 'V-VCFA-9X-000270'
  tag rid: 'SV-VCFA-9X-000270'
  tag stig_id: 'VCFA-9X-000270'
  tag cci: ['CCI-003627']
  tag nist: ['AC-2 (3) (a)']

  describe powercli_command('Get-SsoPersonUser -Domain vsphere.local -Name "K/M" | Select-Object -ExpandProperty Disabled') do
    its('stdout.strip') { should cmp 'true' }
  end
  describe powercli_command('Get-SsoPersonUser -Domain vsphere.local -Name "krbtgt/VSPHERE.LOCAL" | Select-Object -ExpandProperty Disabled') do
    its('stdout.strip') { should cmp 'true' }
  end
end
