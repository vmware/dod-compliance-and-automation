control 'ESXI-67-000072' do
  title 'The ESXi host must have all security patches and updates installed.'
  desc  "Installing software updates is a fundamental mitigation against the
exploitation of publicly known vulnerabilities."
  desc  'rationale', ''
  desc  'check', "
    If vCenter Update Manager is used on the network, it can be used to scan
all hosts for missing patches.

    From the vSphere Client, go to Hosts and Clusters >> Updates.

    Check under \"Attached Baselines\" and verify that a compliance check has
been run.

    If vCenter Update Manager is not used, host compliance status must be
determined manually by the build number.

    VMware KB 1014508 can be used to correlate patches with build numbers.

    If the ESXi host does not have the latest patches, this is a finding.

    If the ESXi host is not on a supported release, this is a finding.

    VMware also publishes Advisories on security patches and offers a way to
subscribe to email alerts for them.

    Go to: https://www.vmware.com/support/policies/security_response
  "
  desc 'fix', "
    If vCenter Update Manager is used on the network, hosts can be remediated
from the vSphere Web Client.

    From the vSphere Client, go to Hosts and Clusters >> Updates.

    Check under \"Attached Baselines\". If there are no baselines attached,
select the drop-down \"Attach >> Attach Baseline or Baseline Group\". Select
\"attach\" and select the type of patches.

    Click on Check Compliance to check Host(s) Compliance.

    To manually remediate a host, the patch file must be copied locally and the
following command run from an SSH session connected to the ESXi host or from
the ESXi shell:

    esxcli software vib update -d <path to offline patch bundle.zip>
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239325'
  tag rid: 'SV-239325r674904_rule'
  tag stig_id: 'ESXI-67-000072'
  tag fix_id: 'F-42517r674903_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}).ExtensionData.Config.Product.build"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "#{input('esxiBuildNumber')}" }
  end
end
