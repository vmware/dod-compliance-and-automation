control 'PHTN-30-000004' do
  title 'The Photon operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc  'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to denial-of-service attacks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    #  grep \"^[^#].*maxlogins.*\" /etc/security/limits.conf

    Expected result:

    *       hard    maxlogins       10

    If the output does not match the expected result, this is a finding.

    Note: The expected result may be repeated multiple times.
  "
  desc 'fix', "
    At the command line, execute the following command:

    # echo '*       hard    maxlogins       10' >> /etc/security/limits.conf
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000004'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe limits_conf('/etc/security/limits.conf') do
    its('*') { should include ['hard', 'maxlogins', '10'] }
  end
end
