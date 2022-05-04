control 'VCSA-70-000057' do
  title 'vCenter Server plugins must be verified.'
  desc  "
    The vCenter Server includes a vSphere Client extensibility framework, which provides the ability to extend the vSphere Client with menu selections or toolbar icons that provide access to vCenter Server add-on components or external, Web-based functionality.

    vSphere Client plugins or extensions run at the same privilege level as the user. Malicious extensions might masquerade as useful add-ons while compromising the system by stealing credentials or incorrectly configuring the system.

    Additionally, vCenter comes with a number of plugins pre-installed that may or may not be necessary for proper operation.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Solutions >> Client Plug-Ins.

    View the Installed/Available Plug-ins list and verify they are all identified as authorized VMware, Third-party (Partner) and/or site-specific approved plug-ins.

    If any Installed/Available plug-ins in the viewable list cannot be verified as an allowed vSphere Client plug-ins from trusted sources or are not in active use, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Solutions >> Client Plug-Ins, click the radio button next to the unknown plug-in and click disable.

    If the plugin will not be needed in the future, proceed to uninstall the plug-in.

    To uninstall plug-ins, do the following:

    If you have vCenter Server in linked mode, perform this procedure on the vCenter Server that is used to install the plug-in initially, then restart the vCenter Server services on the linked vCenter Server.

    In a web browser, navigate to http://vCenter_Server_name_or_IP/mob.

    Where vCenter_Server_name_or_IP/mob is the name of your vCenter Server or its IP address.

    Click Content.

    Click ExtensionManager.

    Select and copy the name of the plug-in you want to remove from the list of values under Properties. For a list of default plug-ins, see the Additional Information section of this article.

    Click UnregisterExtension. A new window appears.

    Paste the name of the plug-in and click Invoke Method. This removes the plug-in.

    Close the window.

    Refresh the Managed Object Type:ManagedObjectReference:ExtensionManager window to verify that the plug-in is removed successfully.

    Note: If the plug-in still appears, you may have to restart the vSphere Client.

    Note: You may have to enable the Managed Object Browser (MOB) temporarily if previously disabled.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000057'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
