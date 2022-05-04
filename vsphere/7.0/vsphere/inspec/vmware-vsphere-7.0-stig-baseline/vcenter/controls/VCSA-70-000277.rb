control 'VCSA-70-000277' do
  title 'The vCenter Server must be isolated from the public Internet but must still allow for patch notification and delivery.'
  desc  "
    vCenter and the embedded Lifecycle Manager system must never have a direct route to the Internet. Despite this, updates and patches sourced from VMware on the Internet must be delivered in a timeley manner.

    There are two methods to accomplish this, a proxy server and the Update Manager Download Service (UMDS). UMDS is an optional module for Lifecycle Manager that fetches upgrades for virtual appliances, patch metadata, patch binaries and notifications that would not otherwise be available to an isolated Lifecycle Manager directly.

    Alternatively, a proxy for Lifecycle Manager can be configured to allowed controlled, limited access to the public internet for the sole purpose of patch gathering. Either solution mitigates the risk of Internet connectivity by limiting it's scope and usage.
  "
  desc  'rationale', ''
  desc  'check', "
    Check the following conditions:

    1. Lifecycle Manager must be configured to use the Update Manager Download Server.

    OR

    2. Lifecycle Manager must be configured to use a proxy server for access to VMware patch repositories.

    OR

    3. Lifecycle Manager must disable internet patch repositories and any patches must be manually validated and imported as needed.

    Option 1:

    From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

    Click the \"Change Download Source\" button.

    Verify that the \"Download patches from a UMDS shared repository\" radio button is selected and that a valid UMDS repository is supplied.

    Click \"Cancel\".

    If this is not set, this is a finding.

    Option 2:

    From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

    Click the \"Change Download Source\" button.

    Verify that the \"Download patches directly from the internet\" radio button is selected.

    Click \"Cancel\".

    Navigate to the vCenter Server Management interface at https://<vcenter dns>:5480 >> Networking >> Proxy Settings.

    Verify that \"HTTPS\" is \"Enabled\".

    Click the \"HTTPS\" row.

    Verify that the proxy server configuration is accurate.

    If this is not set, this is a finding.

    Option 3:

    From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Downloads.

    Verify the \"Automatic downloads\" option is disabled.

    From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

    Verify any download sources are disabled.

    If this is not set, this is a finding.
  "
  desc 'fix', "
    Option 1:

    From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

    Click the \"Change Download Source\" button.

    Select the \"Download patches from a UMDS shared repository\" radio button and supply a valid UMDS repository.

    Click \"Save\".

    Option 2:

    From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Setup.

    Click the \"Change Download Source\" button.

    Select the \"Download patches directly from the internet\" radio button.

    Click \"Save\".

    Navigate to the vCenter Server Management interface at https://<vcenter dns>:5480 >> Networking >> Proxy Settings.

    Click \"Edit\".

    Slide \"HTTPS\" to \"Enabled\".

    Supply the appropriate proxy server configuration.

    Click \"Save\".

    Option 3:

    From the vSphere Client, go to Lifecycle Manager >> Settings >> Patch Downloads.

    Click \"Edit\" and uncheck \"Download patches\". Then under \"Patch Setup\" select each download source and click Disable.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000277'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
