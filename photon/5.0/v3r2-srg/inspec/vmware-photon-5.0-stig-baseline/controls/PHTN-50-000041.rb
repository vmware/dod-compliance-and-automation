control 'PHTN-50-000041' do
  title 'The Photon operating system must enforce one day as the minimum password lifetime.'
  desc  "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify one day as the minimum password lifetime:

    # grep '^PASS_MIN_DAYS' /etc/login.defs

    If \"PASS_MIN_DAYS\" is not set to 1, is missing or commented out, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/login.defs

    Add or update the following line:

    PASS_MIN_DAYS 1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag gid: 'V-PHTN-50-000041'
  tag rid: 'SV-PHTN-50-000041'
  tag stig_id: 'PHTN-50-000041'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  describe login_defs do
    its('PASS_MIN_DAYS') { should cmp '1' }
  end
end
