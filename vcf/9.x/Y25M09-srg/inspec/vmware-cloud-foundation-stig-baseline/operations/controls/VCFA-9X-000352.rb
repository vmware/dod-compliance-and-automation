control 'VCFA-9X-000352' do
  title 'VMware Cloud Foundation Operations must enable FIPS-validated cryptography.'
  desc  'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. '
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Administration >> Control Panel >> Cluster Management.

    View the cluster status to verify FIPS mode is enabled.

    For example:

    Cluster Status (FIPS 140-2 Enabled)

    If FIPS 140-2 is not enabled , this is a finding.
  "
  desc 'fix', "
    Enabling FIPS must be done from the admin portal. Login to the admin portal (/admin/) as an administrator.

    Go to Administrator Settings >> Security Settings.

    Click the \"Activate FIPS\" button, then click \"Yes\".

    Once you activate FIPS, the cluster restarts and is not available during this time. The cluster nodes are rebooted and once the cluster is online, all the nodes will have FIPS activated.

    Note: The cluster must be offline in order to activate FIPS mode, and once FIPS mode is activated, it can never be de-activated.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000555'
  tag gid: 'V-VCFA-9X-000352'
  tag rid: 'SV-VCFA-9X-000352'
  tag stig_id: 'VCFA-9X-000352'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
