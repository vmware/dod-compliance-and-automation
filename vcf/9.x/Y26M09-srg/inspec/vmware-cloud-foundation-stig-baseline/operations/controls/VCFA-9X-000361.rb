control 'VCFA-9X-000361' do
  title 'VMware Cloud Foundation Operations must include only approved trust anchors in trust stores or certificate stores managed by the organization.'
  desc  'Public key infrastructure (PKI) certificates are certificates with visibility external to organizational systems and certificates related to the internal operations of systems, such as application-specific time services. In cryptographic systems with a hierarchical structure, a trust anchor is an authoritative source (i.e., a certificate authority) for which trust is assumed and not derived. A root certificate for a PKI system is an example of a trust anchor. A trust store or certificate store maintains a list of trusted root certificates.'
  desc  'rationale', ''
  desc  'check', "
    Certificate Authority (CA) or root certificates are used for establishing the outgoing connections from VCF Operations. CA Certificates imported will be used in the following VCF Operations domains: Authentication Sources, Outbound Plugins, and Adapter Endpoints.

    From VCF Operations, go to Administration >> Control Panel >> Trusted Certificates.

    Review the configured trusted certificates of type \"CERTIFICATE_AUTHORITY\" for any unknown trusted root certificates.

    If there are any unknown or unapproved trusted root certificates present, this is a finding.
  "
  desc 'fix', "
    From VCF Operations, go to Administration >> Control Panel >> Trusted Certificates.

    Locate the unapproved trusted root certificate in the list.

    Click the menu button next to the target and select Delete and click Yes to confirm the removal.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000910'
  tag gid: 'V-VCFA-9X-000361'
  tag rid: 'SV-VCFA-9X-000361'
  tag stig_id: 'VCFA-9X-000361'
  tag cci: ['CCI-004909']
  tag nist: ['SC-17 b']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
