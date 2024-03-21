control 'PHTN-50-000007' do
  title 'The Photon operating system must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc  "
    Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to Denial of Service (DoS) attacks.

    This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the limit for the number of concurrent sessions:

    # grep \"^[^#].*maxlogins.*\" /etc/security/limits.conf

    Example result:

    *       hard    maxlogins       10

    If \"* hard maxlogins\" is not configured to \"10\", this is a finding.

    Note: The expected result may be repeated multiple times.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/limits.conf

    Add or update the following line:

    *       hard    maxlogins       10
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag gid: 'V-PHTN-50-000007'
  tag rid: 'SV-PHTN-50-000007'
  tag stig_id: 'PHTN-50-000007'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe limits_conf('/etc/security/limits.conf') do
    its('*') { should include ['hard', 'maxlogins', '10'] }
  end
end
