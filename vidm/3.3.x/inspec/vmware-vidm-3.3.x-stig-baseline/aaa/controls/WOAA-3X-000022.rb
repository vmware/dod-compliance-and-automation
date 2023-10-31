control 'WOAA-3X-000022' do
  title 'Workspace ONE Access must be configured to disable non-essential modules.'
  desc  "
    It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

    Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

    Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    On the VMware Identity Manager console Identity & Access Management tab, select Setup.

    On the Connectors page, select the Worker link for the connector that is being configured.

    Click Auth Adapters and check the status.

    If any auth adaptor isn't being used but is enabled, this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    On the VMware Identity Manager console Identity & Access Management tab, select Setup.

    On the Connectors page, select the Worker link for the connector that is being configured.

    Click Auth Adapters and click on the one to be disabled.

    Uncheck the Enable box and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AAA-000670'
  tag gid: 'V-WOAA-3X-000022'
  tag rid: 'SV-WOAA-3X-000022'
  tag stig_id: 'WOAA-3X-000022'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
