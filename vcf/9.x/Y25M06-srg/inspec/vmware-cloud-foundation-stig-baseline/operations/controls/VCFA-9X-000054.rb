control 'VCFA-9X-000054' do
  title 'VMware Cloud Foundation must use multifactor authentication for access to privileged accounts.'
  desc  "
    Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

    Multifactor authentication requires the use of two or more factors to achieve authentication.

    Factors include:
    (i) Something a user knows (e.g., password/PIN);
    (ii) Something a user has (e.g., cryptographic identification device, token); or
    (iii) Something a user is (e.g., biometric).

    A privileged account is defined as an information system account with authorizations of a privileged user.

    Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).
  "
  desc  'rationale', ''
  desc  'check', "
    VMware Cloud Foundation offers Single Sign-On (SSO) capability that allows users to access VCF components, including vCenter, NSX, Operations, Automation, Operations Orchestrator, Operations HCX, Operations for Logs, and Operations for Networks, with one set of credentials through a configured identity provider. If the identity provider supports multifactor authentication this will be inherited by VCF components that are configured to use it.

    From VCF Operations, go to Fleet Management >> Identity & Access.

    Review each VCF instance, management component, and others.

    If VCF components are not configured to use Single Sign-On with an identity provider that supports multifactor authentication, this is a finding.
  "
  desc  'fix', "
    For complete details on configuring VCF SSO, refer to the product documentation.

    A 3rd party identity provider that supports multifactor authentication must be available prior to configuring VCF SSO. Okta, Ping Identity, Microsoft Entra ID, Microsoft ADFS, or any identity provider that supports SAML 2.0 is supported.

    From VCF Operations, go to Fleet Management >> Identity & Access >> SSO Overview.

    To begin configuring SSO select a VCF instance from the dropdown.

    Click Start on \"Choose deployment mode\". Select either embedded or appliance for the identity broker deployment mode and click Next.

    Click Start on \"Configure Identity Provider\".

    Choose an identity provider from the list of supported identity providers and click Next.

    Complete the identity provider configuration wizard for the selected identity provider.

    Click Edit on \"Configure Components\". Add any additional vCenter or NSX components as needed and click Configure.

    Click Finish Setup to complete the initial SSO configuration.

    After initial setup is complete, the additional components deployed need to be connected to VCF SSO.

    For Operations and Automation this is done by selecting each under VCF Management and clicking Continue to start the configure client process then selecting an identity broker and clicking Configure.

    For Operations for Logs, Operations for Networks, Operations Orchestrator, and Operations HCX this is done by generating an OIDC client in the VCF SSO interface for each and completing the configuration in that component's management interface using the OIDC client information.

    Note: Only licensed VCF components that are version 9.0 or later and are not part of enhanced link mode are supported for enabling SSO access.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000149'
  tag satisfies: ['SRG-APP-000080', 'SRG-APP-000148', 'SRG-APP-000150', 'SRG-APP-000154', 'SRG-APP-000155', 'SRG-APP-000163', 'SRG-APP-000180', 'SRG-APP-000820', 'SRG-APP-000825']
  tag gid: 'V-VCFA-9X-000054'
  tag rid: 'SV-VCFA-9X-000054'
  tag stig_id: 'VCFA-9X-000054'
  tag cci: ['CCI-000166', 'CCI-000764', 'CCI-000765', 'CCI-000766', 'CCI-000804', 'CCI-003627', 'CCI-004046', 'CCI-004047']
  tag nist: ['AC-2 (3) (a)', 'AU-10', 'IA-2', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (6) (a)', 'IA-2 (6) (b)', 'IA-8']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
