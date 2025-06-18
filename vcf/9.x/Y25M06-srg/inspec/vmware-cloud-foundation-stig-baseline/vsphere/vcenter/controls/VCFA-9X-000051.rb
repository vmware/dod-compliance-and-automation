control 'VCFA-9X-000051' do
  title 'VMware Cloud Foundation vCenter Server client plugins must be verified.'
  desc  "
    The vCenter Server includes a vSphere Client extensibility framework, which provides the ability to extend the vSphere Client with menu selections or toolbar icons that provide access to vCenter Server add-on components or external, web-based functionality.

    vSphere Client plugins or extensions run at the same privilege level as the user. Malicious extensions might masquerade as useful add-ons while compromising the system by stealing credentials or incorrectly configuring the system.

    Additionally, vCenter comes with a number of plugins preinstalled that are necessary for proper operation.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Solutions >> Client Plugins.

    View the Installed/Available Plugins list and verify they are all identified as authorized VMware, third-party (partner), and/or site-specific approved plugins.

    If any installed/available plugins in the viewable list cannot be verified as allowed vSphere Client plugins from trusted sources or are not in active use, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Solutions >> Client Plugins.

    Click on the name of the target plugin.

    Select the plugin and click \"Remove\" and \"Yes\" to confirm.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141'
  tag gid: 'V-VCFA-9X-000051'
  tag rid: 'SV-VCFA-9X-000051'
  tag stig_id: 'VCFA-9X-000051'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
    skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
  end
end
