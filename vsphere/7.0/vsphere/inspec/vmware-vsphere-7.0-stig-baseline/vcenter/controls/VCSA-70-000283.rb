control 'VCSA-70-000283' do
  title 'The vCenter Server must disable Username/Password and Windows Integrated Authentication.'
  desc  'All forms of authentication other than Common Access Card (CAC) must be disabled. Password authentication can be temporarily reenabled for emergency access to the local Single Sign-On (SSO) accounts or Active Directory user/pass accounts, but it must be disabled as soon as CAC authentication is functional.'
  desc  'rationale', ''
  desc  'check', "
    If a federated identity provider is configured and used for an identity source, this is not applicable.

    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider >> Smart Card Authentication.

    Under \"Authentication method\", examine the allowed methods.

    If \"Smart card authentication\" is not enabled and \"Password and windows session authentication\" is not disabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider >> Smart Card Authentication.

    Next to \"Authentication method\", click \"Edit\".

    Select the radio button to \"Enable smart card authentication\".

    Click \"Save\".

    To reenable password authentication for troubleshooting purposes, run the following command on the vCenter Server Appliance:

    # /opt/vmware/bin/sso-config.sh -set_authn_policy -pwdAuthn true -winAuthn false -certAuthn false -securIDAuthn false -t vsphere.local
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-256363'
  tag rid: 'SV-256363r885700_rule'
  tag stig_id: 'VCSA-70-000283'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('embeddedIdp')
    describe powercli_command('(Get-SsoAuthenticationPolicy).SmartCardAuthnEnabled') do
      its('stdout.strip') { should cmp 'true' }
    end
    describe powercli_command('(Get-SsoAuthenticationPolicy).PasswordAuthnEnabled') do
      its('stdout.strip') { should cmp 'false' }
    end
    describe powercli_command('(Get-SsoAuthenticationPolicy).WindowsAuthnEnabled') do
      its('stdout.strip') { should cmp 'false' }
    end
  else
    describe 'This check is a manual or policy based check' do
      skip 'This must be reviewed manually'
    end
  end
end
