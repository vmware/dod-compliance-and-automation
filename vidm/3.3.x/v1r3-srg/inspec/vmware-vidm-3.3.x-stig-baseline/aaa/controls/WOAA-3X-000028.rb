control 'WOAA-3X-000028' do
  title 'Workspace ONE Access must be configured to require multifactor authentication using Common Access Card (CAC) for authenticating user accounts.'
  desc  "
    To assure accountability and prevent unauthenticated access, users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

    Multifactor authentication uses two or more factors to achieve authentication.

    Factors include:
    (i) Something you know (e.g., password/PIN);
    (ii) Something you have (e.g., cryptographic identification device, token); or
    (iii) Something you are (e.g., biometric).

    Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

    Applications integrating with the DoD Active Directory and using the DoD CAC are examples of compliant multifactor authentication solutions.
  "
  desc  'rationale', ''
  desc  'check', "
    Navigate to the Workspace ONE Access login page in a new browser session.

    If your CAC is inserted but you are not prompted to select a certificate or enter your PIN, this is a finding.
  "
  desc 'fix', 'See the accompanying Smart Card configuraiton guide for Workspace ONE Access.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000150-AAA-000410'
  tag gid: 'V-WOAA-3X-000028'
  tag rid: 'SV-WOAA-3X-000028'
  tag stig_id: 'WOAA-3X-000028'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
