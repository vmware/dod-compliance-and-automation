control 'ESXI-80-000006' do
  title 'The ESXi host must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via the Direct Console User Interface (DCUI).'
  desc %q(Display of a standardized and approved use notification before granting access to the host ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DOD policy. Use the following verbiage for a host that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) VMM (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for VMMs that have severe limitations on the number of characters that can be displayed in the banner:

"I've read (literal ampersand) consent to terms in IS user agreem't.")
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Annotations.WelcomeMessage" value and verify it contains the standard mandatory DOD notice and consent banner.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage

If the "Annotations.WelcomeMessage" setting does not contain the standard mandatory DOD notice and consent banner, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Annotations.WelcomeMessage" value and set it to the following. Click "OK".

{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{hostname} , {ip}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{esxproduct} {esxversion}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{memory} RAM{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:white} {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By      {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  using this IS (which includes any device attached to this IS), you consent to the following conditions:                 {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited     {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law      {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          enforcement (LE), and counterintelligence (CI) investigations.                                                  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       At any time, the USG may inspect and seize data stored on this IS.                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       Communications using, or data stored on, this IS are not private, are subject to routine monitoring,            {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          interception, and search, and may be disclosed or used for any USG-authorized purpose.                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not     {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          for your personal benefit or privacy.                                                                           {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching    {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          or monitoring of the content of privileged communications, or work product, related to personal representation  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work       {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          product are private and confidential. See User Agreement for details.                                           {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{align:left}{bgcolor:dark-grey}{color:white}  <F2> Accept Conditions and Customize System / View Logs{/align}{align:right}<F12> Accept Conditions and Shut Down/Restart  {bgcolor:black} {/color}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Set-AdvancedSetting -Value "<Banner text above>"'
  impact 0.5
  tag check_id: 'C-62469r933246_chk'
  tag severity: 'medium'
  tag gid: 'V-258729'
  tag rid: 'SV-258729r933248_rule'
  tag stig_id: 'ESXI-80-000006'
  tag gtitle: 'SRG-OS-000023-VMM-000060'
  tag fix_id: 'F-62378r933247_fix'
  tag satisfies: ['SRG-OS-000023-VMM-000060', 'SRG-OS-000024-VMM-000070']
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']

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
      result = powercli_command("Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Select-Object -ExpandProperty Value")
      describe.one do
        describe result do
          its('stdout.strip') { should match 'You are accessing a U.S. Government' }
        end
        describe result do
          its('stdout.strip') { should match "I've read & consent to terms in IS user agreem't" }
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
