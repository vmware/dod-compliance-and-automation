control 'VCFA-9X-000348' do
  title 'VMware Cloud Foundation Operations must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.'
  desc  'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. '
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Administration >> Global Settings >> User Access >> Password Policy >> Policy Definition >> Account Lockout.

    Review the configured lockout policies.

    If the account lockout \"Maximum number of consecutive failed login attempts\" is not configured to 3, this is a finding.

    If the account lockout \"Time interval between failures\" is not configured to 900 seconds or more, this is a finding.

    If the account lockout \"Length of lockout period\" is not configured to 900 seconds or more, this is a finding.
  "
  desc 'fix', "
    From VCF Operations, go to Administration >> Global Settings >> User Access >> Password Policy >> Policy Definition >> Account Lockout.

    Note: The Password Policy Activation is covered by another control.

    Configure the following settings:

    Configure \"Maximum number of consecutive failed login attempts\" to 3.

    Configure \"Time interval between failures\" to 900 seconds.

    Configure \"Length of lockout period\" to 900 seconds.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000065'
  tag gid: 'V-VCFA-9X-000348'
  tag rid: 'SV-VCFA-9X-000348'
  tag stig_id: 'VCFA-9X-000348'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
