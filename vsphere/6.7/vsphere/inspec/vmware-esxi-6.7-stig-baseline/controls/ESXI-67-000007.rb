control 'ESXI-67-000007' do
  title "The ESXi host must display the Standard Mandatory DoD Notice and
Consent Banner before granting access to the system via the DCUI."
  desc  "Failure to display the DoD logon banner prior to a logon attempt will
negate legal proceedings resulting from unauthorized access to system resources.


  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Advanced System Settings.

    Select the \"Annotations.WelcomeMessage\" value and verify it contains the
DoD logon banner to follow.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage

    Check for either of the following logon banners based on the character
limitations imposed by the system. An exact match of the text is required. If
one of these banners is not displayed, this is a finding.

    You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests- -not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.

    OR

    I've read & consent to terms in IS user agreem't.

    If the DCUI logon screen does not display the DoD logon banner, this is a
finding.
  "
  desc 'fix', "
    From a PowerCLI command prompt while connected to the ESXi host, copy the
following contents into a script(.ps1 file) and run to set the DCUI screen to
display the DoD logon banner:

    <script begin>

    $value = @\"
    {bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{hostname}
, {ip}{/color}{/bgcolor}{/align}
    {bgcolor:black}
{/color}{align:left}{bgcolor:black}{color:yellow}{esxproduct}
{esxversion}{/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{memory}
RAM{/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:black}{color:white}
{/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}

                               {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  You are
accessing a U.S. Government (USG) Information System (IS) that is provided for
USG-authorized use only. By      {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  using
this IS (which includes any device attached to this IS), you consent to the
following conditions:                 {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}

                               {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -
The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited     {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}
to, penetration testing, COMSEC monitoring, network operations and defense,
personnel misconduct (PM), law      {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}
enforcement (LE), and counterintelligence (CI) investigations.
                                {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}

                               {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -
At any time, the USG may inspect and seize data stored on this IS.
                                {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}

                               {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -
Communications using, or data stored on, this IS are not private, are subject
to routine monitoring,            {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}
interception, and search, and may be disclosed or used for any USG-authorized
purpose.                          {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}

                               {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -
This IS includes security measures (e.g., authentication and access controls)
to protect USG interests--not     {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}
for your personal benefit or privacy.
                                {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}

                               {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -
Notwithstanding the above, using this IS does not constitute consent to PM, LE
or CI investigative searching    {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}
or monitoring of the content of privileged communications, or work product,
related to personal representation  {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}
or services by attorneys, psychotherapists, or clergy, and their assistants.
Such communications and work       {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}
product are private and confidential. See User Agreement for details.
                                {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}

                               {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    {bgcolor:black} {/color}{align:left}{bgcolor:dark-grey}{color:white}  <F2>
Accept Conditions and Customize System / View Logs{/align}{align:right}<F12>
Accept Conditions and Shut Down/Restart  {bgcolor:black}
{/color}{/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}

                      {/color}{/bgcolor}
    \"@

    Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage |
Set-AdvancedSetting -Value $value

    <script end>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-VMM-000060'
  tag satisfies: ['SRG-OS-000023-VMM-000060', 'SRG-OS-000024-VMM-000070']
  tag gid: 'V-239264'
  tag rid: 'SV-239264r674721_rule'
  tag stig_id: 'ESXI-67-000007'
  tag fix_id: 'F-42456r674720_fix'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Select-Object -ExpandProperty Value"

  describe.one do
    describe powercli_command(command) do
      its('stdout.strip') { should match 'You are accessing a U.S. Government' }
    end
    describe powercli_command(command) do
      its('stdout.strip') { should match "I've read & consent to terms in IS user agreem't" }
    end
  end
end
