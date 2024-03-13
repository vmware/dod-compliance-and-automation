control 'VCSA-80-000057' do
  title 'vCenter Server plugins must be verified.'
  desc 'The vCenter Server includes a vSphere Client extensibility framework, which provides the ability to extend the vSphere Client with menu selections or toolbar icons that provide access to vCenter Server add-on components or external, web-based functionality.

vSphere Client plugins or extensions run at the same privilege level as the user. Malicious extensions might masquerade as useful add-ons while compromising the system by stealing credentials or incorrectly configuring the system.

Additionally, vCenter comes with a number of plugins preinstalled that may or may not be necessary for proper operation.'
  desc 'check', 'From the vSphere Client, go to Administration >> Solutions >> Client Plug-Ins.

View the Installed/Available Plug-ins list and verify they are all identified as authorized VMware, third-party (partner), and/or site-specific approved plug-ins.

If any installed/available plug-ins in the viewable list cannot be verified as allowed vSphere Client plug-ins from trusted sources or are not in active use, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Solutions >> Client Plug-Ins, click the radio button next to the unknown plug-in, and click "Disable".

If the plugin will not be needed in the future, proceed to uninstall the plug-in.

To uninstall plug-ins, do the following:

If vCenter Server is in linked mode, perform this procedure on the vCenter Server that is used to install the plug-in initially and then restart the vCenter Server services on the linked vCenter Server:

In a web browser, navigate to "http://vCenter_Server_name_or_IP/mob", where "vCenter_Server_name_or_IP/mob" is the name of the vCenter Server or its IP address.

Click "Content".

Click "ExtensionManager".

Select and copy the name of the plug-in to be removed from the list of values under "Properties".

Click "UnregisterExtension". A new window appears.

Paste the name of the plug-in and click "Invoke Method". This removes the plug-in.

Close the window.

Refresh the Managed Object Type:ManagedObjectReference:ExtensionManager window to verify the plug-in is removed successfully.

Note: If the plug-in still appears, restart the vSphere Client.

Note: The Managed Object Browser (MOB) may have to be enabled temporarily if it was disabled previously.'
  impact 0.5
  tag check_id: 'C-62648r934380_chk'
  tag severity: 'medium'
  tag gid: 'V-258908'
  tag rid: 'SV-258908r934382_rule'
  tag stig_id: 'VCSA-80-000057'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-62557r934381_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
