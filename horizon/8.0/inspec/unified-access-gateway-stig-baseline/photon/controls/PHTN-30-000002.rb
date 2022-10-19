control 'PHTN-30-000002' do
  title 'The Photon operating system must automatically lock an account when three unsuccessful logon attempts occur.'
  desc  'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command(s):

    # grep pam_tally2 /etc/pam.d/system-auth

    Expected result:

    auth       required pam_tally2.so deny=3 onerr=fail audit even_deny_root unlock_time=900 root_unlock_time=300

    # grep pam_tally2 /etc/pam.d/system-account

    Expected result:

    account    required pam_tally2.so onerr=fail audit

    If the output does not list the pam_tally2 options as configured in the expected results, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-auth

    Remove any existing \"pam_tally2.so\" line and add the following line after the pam_unix.so statement:

    auth       required pam_tally2.so deny=3 onerr=fail audit even_deny_root unlock_time=900 root_unlock_time=300

    Navigate to and open:

    /etc/pam.d/system-account

    Remove any existing \"pam_tally2.so\" line and add the following line after the pam_unix.so statement:

    account    required pam_tally2.so onerr=fail audit

    Note: On vCenter appliances you must edit the equivalent file under /etc/applmgmt/appliance if one exists for the changes to persist after a reboot.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000329-GPOS-00128']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000002'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']

  # match after pam_unix.so and with options in any order on pam_tally2
  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /^auth\s*required\s*pam_unix\.so.*\n(^auth\s*required\s*pam_tally2\.so\s*(?=.*\bdeny=3\b)(?=.*\bonerr=fail\b)(?=.*\baudit\b)(?=.*\beven_deny_root\b)(?=.*\bunlock_time=900\b)(?=.*\broot_unlock_time=300\b).*$)/ }
  end

  # match after pam_unix.so and with options in any order on pam_tally2
  describe file('/etc/pam.d/system-account') do
    its('content') { should match /^account\s*required\s*pam_unix\.so.*\n(^account\s*required\s*pam_tally2\.so\s*(?=.*\bonerr=fail\b)(?=.*\baudit\b).*$)/ }
  end
end
