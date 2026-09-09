control 'VLMA-8X-000007' do
  title 'VMware Aria Suite Lifecycle must have all security patches and updates installed.'
  desc  'Installing software updates is a fundamental mitigation against the exploitation of publicaly-known vulnerabilities.'
  desc  'rationale', ''
  desc  'check', "
    Check for and download available updates by using either the online or offline process.

    Online

    Login to VMware Aria Suite Lifecycle as the admin@local account.

    Select \"Lifecycle Operations\" >> Settings >> Servers & Accounts >> Binary Mapping >> Patch Binaries.

    Click \"Check Patches Online\" to initiate download of any available patches.

    Offline

    Login to VMware Aria Suite Lifecycle as the admin@local account.

    Select \"Lifecycle Operations\" >> Settings >> Servers & Accounts >> Binary Mapping >> Patch Binaries.

    Click \"Add Patch Binary\" to manual upload a previously downloaded patch.

    To check if patches are available for install select \"Lifecycle Operations\" >> Settings >> Sytem Patches >> New Patch

    If VMware Aria Suite Lifecycle does not have the latest patches/updates, this is a finding.

    If VMware Aria Suite Lifecycle is not on a supported release, this is a finding.
  "
  desc 'fix', "
    To install available patches perform the following:

    Login to VMware Aria Suite Lifecycle as the admin@local account.

    Select \"Lifecycle Operations\" >> Settings >> System Administration >> System Patches >> New Patch

    Select an available patch from the list and click next.

    Review the patch installation and click Install.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag gid: 'V-VLMA-8X-000007'
  tag rid: 'SV-VLMA-8X-000007'
  tag stig_id: 'VLMA-8X-000007'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
