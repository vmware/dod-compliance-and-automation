control 'PHTN-30-000073' do
  title 'The Photon operating system must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc  'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep pam_faildelay /etc/pam.d/system-auth|grep --color=always \"delay=\"

    Expected result:

    auth       optional pam_faildelay.so delay=4000000

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-auth

    Remove any existing \"pam_faildelay\" line and add the follwing line at the end of the file:

    auth       optional pam_faildelay.so delay=4000000

    Note: On vCenter appliances you must edit the equivalent file under /etc/applmgmt/appliance if one exists for the changes to persist after a reboot.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000073'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /^(?=.*?\bauth\b)(?=.*?\boptional\b)(?=.*?\bpam_faildelay.so\b)(?=.*?\bdelay=4000000\b).*$/ }
  end
end
