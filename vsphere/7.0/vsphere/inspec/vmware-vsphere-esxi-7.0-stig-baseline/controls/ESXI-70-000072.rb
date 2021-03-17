# encoding: UTF-8

control 'ESXI-70-000072' do
  title 'The ESXi host must have all security patches and updates installed.'
  desc  "Installing software updates is a fundamental mitigation against the
exploitation of publicly-known vulnerabilities."
  desc  'rationale', ''
  desc  'check', "
    Determine your current version and build:

    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Summary. Note the version string next to \"Hypervisor:\".

    or

    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following commands:

    # vmware -v

    Since your ESXi hosts should never be able to touch the internet, you must
manually compare your current ESXi version and patch level to the latest
available on vmware.com.

    https://kb.vmware.com/s/article/2143832
  "
  desc  'fix', "
    ESXi can be patched in multiple ways and the fix text here does not cover
all methods.

    Manual patching when image profiles are not used:

    Download the latest \"offline bundle\" .zip update from vmware.com. Verify
the hash. Transfer the file to a datastore accessible by your ESXi host, local
or remote. Put the ESXi host into maintenance mode.

    From an ESXi shell, run the following command(s):

    esxcli software vib update -d <path to offline patch bundle.zip>


    Manual patching when image profiles are used:

    From an ESXi shell, run the following command(s):

    # esxcli software sources profile list -d /vmfs/volumes/<your
datastore>/<bundle name.zip>

    Note the available profiles. You will usually want the one ending in
\"-standard\".

    # esxcli software profile update -p <selected profile> -d
/vmfs/volumes/<your datastore>/<bundle name.zip>

    There will be little output during the update. Once complete, reboot the
host for changes to take effect.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000072'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}).ExtensionData.Config.Product.build"
  describe powercli_command(command) do
    its ('stdout.strip') { should cmp "#{input('esxiBuildNumber')}" }
  end

end

