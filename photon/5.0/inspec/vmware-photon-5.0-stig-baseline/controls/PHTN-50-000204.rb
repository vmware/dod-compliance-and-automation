control 'PHTN-50-000204' do
  title 'The Photon operating system must audit all account modifications.'
  desc  "
    Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to modify an existing account. Auditing account modification actions provides logging that can be used for forensic purposes.

    To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify an audit rule exists to audit account modifications:

    # auditctl -l | grep -E \"(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)\"

    Expected result:

    -w /etc/passwd -p wa -k passwd
    -w /etc/shadow -p wa -k shadow
    -w /etc/group -p wa -k group
    -w /etc/gshadow -p wa -k gshadow

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the \"auditd\" service to be in a running state for accurate results. The \"auditd\" service is enabled in control PHTN-50-000016.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add or update the following lines:

    -w /etc/passwd -p wa -k passwd
    -w /etc/shadow -p wa -k shadow
    -w /etc/group -p wa -k group
    -w /etc/gshadow -p wa -k gshadow

    At the command line, run the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: An \"audit.STIG.rules\" file is provided with this guidance for placement in \"/etc/audit/rules.d\" that contains all rules needed for auditd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag satisfies: ['SRG-OS-000303-GPOS-00120', 'SRG-OS-000467-GPOS-00211']
  tag gid: 'V-PHTN-50-000204'
  tag rid: 'SV-PHTN-50-000204'
  tag stig_id: 'PHTN-50-000204'
  tag cci: ['CCI-000172', 'CCI-001403', 'CCI-002130']
  tag nist: ['AC-2 (4)', 'AU-12 c']

  describe auditd.file('/etc/passwd') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'passwd' }
  end
  describe auditd.file('/etc/shadow') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'shadow' }
  end
  describe auditd.file('/etc/group') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'group' }
  end
  describe auditd.file('/etc/gshadow') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'gshadow' }
  end
end
