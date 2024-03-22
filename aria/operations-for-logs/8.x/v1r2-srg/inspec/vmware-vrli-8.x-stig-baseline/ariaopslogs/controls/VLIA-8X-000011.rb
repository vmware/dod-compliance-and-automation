control 'VLIA-8X-000011' do
  title 'VMware Aria Operations for Logs must protect API SSL connections.'
  desc  "
    Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered.

    This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPSEC.

    Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> SSL.

    If \"Require SSL Connection\" is not enabled under \"API SERVER SSL\", this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> SSL.

    Ensure \"Require SSL Connection\" is enabled  and click save.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000439-AU-004310'
  tag gid: 'V-VLIA-8X-000011'
  tag rid: 'SV-VLIA-8X-000011'
  tag stig_id: 'VLIA-8X-000011'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
  tag mitigations: 'The vRLI applicancer currently uses certificates to very confidentialty of transmitted information. This has beenvalidated as a requirement in later versions in 8.2'

  describe 'SSL Connection configuration is a manual check' do
    skip 'Ensuring Require SSL Connection is enabled is a manual check.'
  end
end
