control 'PHTN-50-000185' do
  title 'The Photon operating system must enforce a delay of at least four seconds between logon prompts following a failed logon attempt in login.defs.'
  desc  'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify a four second delay is configured between logon attempts:

    # grep '^FAIL_DELAY' /etc/login.defs

    Example result:

    FAIL_DELAY 4

    If the \"FAIL_DELAY\" option is not set to 4 or more, is missing or commented out, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/login.defs

    Add or update the following line:

    FAIL_DELAY 4
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag gid: 'V-PHTN-50-000185'
  tag rid: 'SV-PHTN-50-000185'
  tag stig_id: 'PHTN-50-000185'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe login_defs do
    its('FAIL_DELAY') { should cmp >= '4' }
  end
end
