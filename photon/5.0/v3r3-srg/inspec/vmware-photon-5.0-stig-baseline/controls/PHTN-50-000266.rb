control 'PHTN-50-000266' do
  title 'The Photon operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd.'
  desc  'In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify an audit rule exists for all account creations, modifications, disabling, and termination events that affect \"/etc/security/opasswd\" with the following command:

    # auditctl -l | grep -E \"(/etc/security/opasswd)\"

    Expected result:

    -w /etc/security/opasswd -p wa -k opasswd

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the \"auditd\" service to be in a running state for accurate results. The \"auditd\" service is enabled in control PHTN-50-000016.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add or update the following lines:

    -w /etc/security/opasswd -p wa -k opasswd

    At the command line, run the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: An \"audit.STIG.rules\" file is provided with this guidance for placement in \"/etc/audit/rules.d\" that contains all rules needed for auditd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000266'
  tag rid: 'SV-PHTN-50-000266'
  tag stig_id: 'PHTN-50-000266'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe auditd.file('/etc/security/opasswd') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'opasswd' }
  end
end
