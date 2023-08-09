control 'VCSA-70-000277' do
  title 'The vCenter Server must be isolated from the public internet but must still allow for patch notification and delivery.'
  desc 'vCenter and the embedded Lifecycle Manager system must never have a direct route to the internet. Despite this, updates and patches sourced from VMware on the internet must be delivered in a timely manner.

There are two methods to accomplish this: a proxy server and the Update Manager Download Service (UMDS). UMDS is an optional module for Lifecycle Manager that fetches upgrades for virtual appliances, patch metadata, patch binaries, and notifications that would not otherwise be available to an isolated Lifecycle Manager directly.

Alternatively, a proxy for Lifecycle Manager can be configured to allow controlled, limited access to the public internet for the sole purpose of patch gathering. Either solution mitigates the risk of internet connectivity by limiting its scope and use.'
  desc 'check', 'Check the following conditions:

1. Lifecycle Manager must be configured to use the UMDS.

OR

2. Lifecycle Manager must be configured to use a proxy server for access to VMware patch repositories.

OR

3. Lifecycle Manager must disable internet patch repositories and any patches must be manually validated and imported as needed.

Option 1:

From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

Click the "Change Download Source" button.

Verify the "Download patches from a UMDS shared repository" radio button is selected and a valid UMDS repository is supplied.

Click "Cancel".

If this is not set, this is a finding.

Option 2:

From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

Click the "Change Download Source" button.

Verify the "Download patches directly from the internet" radio button is selected.

Click "Cancel".

Navigate to the vCenter Server Management interface at https://<vcenter dns>:5480 >> Networking >> Proxy Settings.

Verify "HTTPS" is "Enabled".

Click the "HTTPS" row.

Verify the proxy server configuration is accurate.

If this is not set, this is a finding.

Option 3:

From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Downloads.

Verify the "Automatic downloads" option is disabled.

From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

Verify any download sources are disabled.

If this is not set, this is a finding.'
  desc 'fix', 'Option 1:

From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

Click the "Change Download Source" button.

Select the "Download patches from a UMDS shared repository" radio button and supply a valid UMDS repository.

Click "Save".

Option 2:

From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

Click the "Change Download Source" button.

Select the "Download patches directly from the internet" radio button.

Click "Save".

Navigate to the vCenter Server Management interface at https://<vcenter dns>:5480 >> Networking >> Proxy Settings.

Click "Edit".

Slide "HTTPS" to "Enabled".

Supply the appropriate proxy server configuration.

Click "Save".

Option 3:

From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Downloads.

Click "Edit" and uncheck "Download patches".

Under "Patch Setup", select each download source and click "Disable".'
  impact 0.5
  tag check_id: 'C-60032r885680_chk'
  tag severity: 'medium'
  tag gid: 'V-256357'
  tag rid: 'SV-256357r885682_rule'
  tag stig_id: 'VCSA-70-000277'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59975r885681_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
