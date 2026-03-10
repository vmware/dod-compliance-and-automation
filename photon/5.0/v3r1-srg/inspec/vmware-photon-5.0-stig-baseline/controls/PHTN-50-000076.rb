control 'PHTN-50-000076' do
  title 'The Photon operating system must audit all account modifications.'
  desc  "
    Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to modify an existing account. Auditing account modification actions provides logging that can be used for forensic purposes.

    To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify an audit rule exists to audit account modifications:

    # auditctl -l | grep -E \"(usermod|groupmod)\"

    Example result:

    -w /usr/sbin/usermod -p x -k usermod
    -w /usr/sbin/groupmod -p x -k groupmod

    If either \"usermod\" or \"groupmod\" are not listed with a permissions filter of at least \"x\", this is a finding.

    Note: This check depends on the \"auditd\" service to be in a running state for accurate results. The \"auditd\" service is enabled in control PHTN-50-000016.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add or update the following lines:

    -w /usr/sbin/usermod -p x -k usermod
    -w /usr/sbin/groupmod -p x -k groupmod

    At the command line, run the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: An \"audit.STIG.rules\" file is provided with this guidance for placement in \"/etc/audit/rules.d\" that contains all rules needed for auditd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag gid: 'V-PHTN-50-000076'
  tag rid: 'SV-PHTN-50-000076'
  tag stig_id: 'PHTN-50-000076'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']

  describe auditd.file('/usr/sbin/usermod') do
    its('permissions') { should include ['x'] }
    its('key') { should cmp 'usermod' }
  end
  describe auditd.file('/usr/sbin/groupmod') do
    its('permissions') { should include ['x'] }
    its('key') { should cmp 'groupmod' }
  end
end
