control 'VLIA-8X-000006' do
  title 'VMware Aria Operations for Logs must disable local accounts after 35 days of inactivity.'
  desc  "
    Inactive identifiers pose a risk to systems and applications. Attackers that are able to exploit an inactive identifier can potentially obtain and maintain undetected access to the application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

    Applications need to track periods of inactivity and disable application identifiers after 35 days of inactivity.

    Management of user identifiers is not applicable to shared information system accounts (e.g., guest and anonymous accounts). It is commonly the case that a user account is the name of an information system account associated with an individual.

    To avoid having to build complex user management capabilities directly into their application, wise developers leverage the underlying OS or other user account management infrastructure (AD, LDAP) that is already in place within the organization and meets organizational user account management requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> General.

    If \"Password Policy Restriction\" is not enabled, this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> General.

    Enable the radio button next to \"Password Policy Restriction\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000163-AU-002470'
  tag satisfies: %w[SRG-APP-000164-AU-002480 SRG-APP-000165-AU-002580 SRG-APP-000166-AU-002490 SRG-APP-000167-AU-002500 SRG-APP-000168-AU-002510 SRG-APP-000169-AU-002520 SRG-APP-000170-AU-002530 SRG-APP-000173-AU-002560 SRG-APP-000174-AU-002570]
  tag gid: 'V-VLIA-8X-000006'
  tag rid: 'SV-VLIA-8X-000006'
  tag stig_id: 'VLIA-8X-000006'
  tag cci: %w[CCI-000192 CCI-000193 CCI-000194 CCI-000195 CCI-000198 CCI-000199 CCI-000200 CCI-000205 CCI-000795 CCI-001619]
  tag nist: ['IA-4 e', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (d)', 'IA-5 (1) (e)']
  tag mitigations: 'We have a prioritized feature request to implement this in the near term. .'

  describe 'Password Policy configuration is a manual check' do
    skip 'Ensuring Password Policy is enabled is a manual check.'
  end
end
