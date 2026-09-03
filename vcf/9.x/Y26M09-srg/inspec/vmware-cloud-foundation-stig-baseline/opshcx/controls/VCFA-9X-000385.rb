control 'VCFA-9X-000385' do
  title 'VMware Cloud Foundation Operations HCX must include only approved trust anchors in trust stores or certificate stores managed by the organization.'
  desc  'Public key infrastructure (PKI) certificates are certificates with visibility external to organizational systems and certificates related to the internal operations of systems, such as application-specific time services. In cryptographic systems with a hierarchical structure, a trust anchor is an authoritative source (i.e., a certificate authority) for which trust is assumed and not derived. A root certificate for a PKI system is an example of a trust anchor. A trust store or certificate store maintains a list of trusted root certificates.'
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations HCX is not deployed, this is not applicable.

    From the VCF Operations HCX Administration interface, go to Administration >> Certificate >> Trusted CA Certificate.

    If there are any unknown or unapproved trusted root certificates present, this is a finding.
  "
  desc 'fix', "
    From the VCF Operations HCX Administration interface, go to Administration >> Certificate >> Trusted CA Certificate.

    For the target trusted certificate, click \"Delete\" from the menu on the left.

    Confirm the deletion by clicking \"Delete\".

    Note: Deleting non-user imported certificates can impact signing chains or otherwise impact VCF Operations HCX appliances.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000910'
  tag gid: 'V-VCFA-9X-000385'
  tag rid: 'SV-VCFA-9X-000385'
  tag stig_id: 'VCFA-9X-000385'
  tag cci: ['CCI-004909']
  tag nist: ['SC-17 b']

  if input('opshcx_deployed')
    describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
      skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Operations HCX is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations HCX is not deployed in the target environment. This control is N/A.'
    end
  end
end
