control 'VCSA-70-000077' do
  title 'The vCenter Server must enable FIPS validated cryptography.'
  desc  "
    FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.

    In vSphere 6.7 and later, ESXi and vCenter Server use FIPS-validated cryptography to protect management interfaces and the VMware Certificate Authority (VMCA).

    vSphere 7.0 Update 2 and later adds additional FIPS-validated cryptography to vCenter Server Appliance. By default, this FIPS validation option is disabled and must be enabled.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Web Client go to Developer Center >> API Explorer.

    From the Select API drop-down menu, select appliance.

    Expand system/security/global_fips >> Get.

    Click execute and then Copy Response to view the results.

    Example response:

    {
        \"enabled\": true
    }

    If global FIPS mode is not enabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Web Client go to Developer Center >> API Explorer.

    From the Select API drop-down menu, select appliance.

    Expand system/security/global_fips >> Put.

    In the response body under \"Try it out\" paste the following:

    {
        \"enabled\": true
    }

    Click Execute.

    Note: The vCenter server reboots after you enable or disable FIPS.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000172'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000077'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
