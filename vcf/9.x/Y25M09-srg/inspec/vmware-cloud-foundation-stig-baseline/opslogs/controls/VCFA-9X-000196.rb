control 'VCFA-9X-000196' do
  title 'VMware Cloud Foundation Operations for Logs must protect the confidentiality and integrity of transmitted information.'
  desc  "
    Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered.

    This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPSEC.

    Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Logs is not deployed, this is not applicable.

    From VCF Operations for Logs, go to Configuration >> SSL.

    Review the \"API Server SSL\" configuration.

    If \"Require SSL Connection\" is not enabled, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Logs, go to Configuration >> SSL.

    Under \"API Server SSL\" click the radio button next to \"Require SSL Connection\" to enable it and click Save.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000439'
  tag gid: 'V-VCFA-9X-000196'
  tag rid: 'SV-VCFA-9X-000196'
  tag stig_id: 'VCFA-9X-000196'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  if input('opslogs_deployed')
    describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
      skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.'
    end
  end
end
