# encoding: UTF-8

control 'V-219301' do
  title "The Ubuntu operating system must limit the number of concurrent
sessions to ten for all accounts and/or account types."
  desc  "Ubuntu operating system management includes the ability to control the
number of users and user sessions that utilize an operating system. Limiting
the number of allowed users and sessions per user is helpful in reducing the
risks related to DoS attacks.

    This requirement addresses concurrent sessions for information system
accounts and does not address concurrent sessions by single users via multiple
system accounts. The maximum number of concurrent sessions should be defined
based on mission needs and the operational environment for each system.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the Ubuntu operating system limits the number of concurrent
sessions to ten for all accounts and/or account types by running the following
command:

    # grep maxlogins /etc/security/limits.conf | grep -v '^* hard maxlogins'

    The result must contain the following line:

    * hard maxlogins 10

    If the \"maxlogins\" item is missing or the value is not set to 10 or less,
it is commented out, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to limit the number of concurrent
sessions to ten for all accounts and/or account types.

    Add the following line to the top of the /etc/security/limits.conf:

    * hard maxlogins 10
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag gid: 'V-219301'
  tag rid: 'SV-219301r508662_rule'
  tag stig_id: 'UBTU-18-010400'
  tag fix_id: 'F-21025r305232_fix'
  tag cci: ['V-100825', 'SV-109929', 'CCI-000054']
  tag nist: ['AC-10']

  describe file('/etc/security/limits.conf') do
    its('content') { should match "^\*\s+hard\s+maxlogins\s+(\\d|10)$" }
  end
end

