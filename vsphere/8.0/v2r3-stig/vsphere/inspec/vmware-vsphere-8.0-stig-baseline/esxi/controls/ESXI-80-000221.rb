control 'ESXI-80-000221' do
  title 'The ESXi host must have all security patches and updates installed.'
  desc 'Installing software updates is a fundamental mitigation against the exploitation of publicly known vulnerabilities.'
  desc 'check', 'Determine the current version and build:

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Summary. Note the version string next to "Hypervisor:".

or

From a Secure Shell (SSH) session connected to the ESXi host, or from the ESXi shell, run the following command:

# vmware -v

If the ESXi host does not have the latest patches, this is a finding.

If the ESXi host is not on a supported release, this is a finding.

The latest ESXi versions and their build numbers can be found here: https://kb.vmware.com/s/article/2143832

VMware also publishes advisories on security patches and offers a way to subscribe to email alerts for them.

Go to: https://www.vmware.com/support/policies/security_response'
  desc 'fix', 'ESXi can be patched in multiple ways, and this fix text does not cover all methods.

Manual patching when image profiles are not used:

- Download the latest "offline bundle" .zip update from vmware.com. Verify the hash.

- Transfer the file to a datastore accessible by the ESXi host, local or remote.

- Put the ESXi host into maintenance mode.

- From an ESXi shell, run the following command:

esxcli software vib update -d <path to offline patch bundle.zip>

Manual patching when image profiles are used:

From an ESXi shell, run the following command:

# esxcli software sources profile list -d /vmfs/volumes/<your datastore>/<bundle name.zip>

Note the available profiles. The organization will usually want the one ending in "-standard".

# esxcli software profile update -p <selected profile> -d /vmfs/volumes/<your datastore>/<bundle name.zip>

There will be little output during the update. Once complete, reboot the host for changes to take effect.'
  impact 0.7
  tag check_id: 'C-62516r933387_chk'
  tag severity: 'high'
  tag gid: 'V-258776'
  tag rid: 'SV-258776r959010_rule'
  tag stig_id: 'ESXI-80-000221'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62425r933388_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      command = "(Get-VMHost -Name #{vmhost}).ExtensionData.Config.Product.build"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp "#{input('esxiBuildNumber')}" }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
