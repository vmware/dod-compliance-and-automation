control 'VCSA-70-000061' do
  title "The vCenter Server must disable Username/Password and Windows
Integrated Authentication."
  desc  "All forms of authentication other than CAC must be disabled. Password
authentication can be temporarily re-enabled for emergency access to the local
SSO accounts or AD user/pass accounts but it must be disable as soon as CAC
authentication is functional."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >>
Configuration >> Identity Provider >> Smart Card Authentication. Under
\"Authentication method\", examine the allowed methods.

    If \"Smart card authentication\" not enabled and \"Password and windows
session authentication\" not disabled , this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >>
Configuration >> Identity Provider >> Smart Card Authentication. Next to
\"Authentication method\", click \"Edit\". Select to radio button to \"Enable
smart card authentication\". Click \"Save\".

    To re-enable password authentication for troubleshooting purposes, run the
following command on the vCenter Server Appliance:

    # /opt/vmware/bin/sso-config.sh -set_authn_policy -pwdAuthn true -winAuthn
false -certAuthn false -securIDAuthn false -t vsphere.local
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000061'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
