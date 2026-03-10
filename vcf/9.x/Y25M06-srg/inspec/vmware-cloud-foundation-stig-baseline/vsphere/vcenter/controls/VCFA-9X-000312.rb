control 'VCFA-9X-000312' do
  title 'The VMware Cloud Foundation vCenter Server must include only approved trust anchors in trust stores or certificate stores managed by the organization.'
  desc  'Public key infrastructure (PKI) certificates are certificates with visibility external to organizational systems and certificates related to the internal operations of systems, such as application-specific time services. In cryptographic systems with a hierarchical structure, a trust anchor is an authoritative source (i.e., a certificate authority) for which trust is assumed and not derived. A root certificate for a PKI system is an example of a trust anchor. A trust store or certificate store maintains a list of trusted root certificates.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Certificates >> Certificate Management >> Trusted Root.

    Review the trusted root certificates in vCenter for any unknown trusted root certificates.

    By default there will be two entries present for the built-in VMware Certificate Authority (VMCA) root certificates that should not be removed.

    If there are any unknown or unapproved trusted root certificates present, this is a finding.
  "
  desc 'fix', "
    By default there will be two entries present for the built-in VMware Certificate Authority (VMCA) root certificates that should not be removed.

    From the vSphere Client, go to Administration >> Certificates >> Certificate Management >> Trusted Root.

    Note the name of the unapproved trusted root certificate to remove. For example \"86C01542FB7176DC3E2D115B21104435CAC\".

    Trusted root certificates can only be removed via the API or CLI.

    To remove a certificate with the API, do the following:

    From the vSphere Client, go to Developer Center >> API Explorer. Select the target vCenter and set the API dropdown to \"vcenter\".

    Locate the \"certificate_management/vcenter/trusted_root_chains\" section.

    Run the GET \"/api/vcenter/certificate-management/vcenter/trusted-root-chains/{chain}\" API and enter the name of the target noted in the previous steps and click Execute.

    Verify the trusted root certificate returned is the intended certificate to remove.

    Run the DELETE \"/api/vcenter/certificate-management/vcenter/trusted-root-chains/{chain}\" API and enter the name of the target noted in the previous steps and click Execute.

    To remove a certificate with the CLI refer to the following KB article:

    https://knowledge.broadcom.com/external/article/326288/removing-ca-certificates-from-the-truste.html
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000910'
  tag gid: 'V-VCFA-9X-000312'
  tag rid: 'SV-VCFA-9X-000312'
  tag stig_id: 'VCFA-9X-000312'
  tag cci: ['CCI-004909']
  tag nist: ['SC-17 b']

  describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
    skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
  end
end
