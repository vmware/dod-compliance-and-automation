control 'PHTN-30-000001' do
  title 'The Photon operating system must audit all account creations.'
  desc  'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E \"(useradd|groupadd)\"

    Expected result:

    -w /usr/sbin/useradd -p x -k useradd
    -w /usr/sbin/groupadd -p x -k groupadd

    If either useradd or groupadd are not listed with a permissions filter of at least 'x', this is a finding.

    Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done in control PHTN-30-000013.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add or update the following lines:

    -w /usr/sbin/useradd -p x -k useradd
    -w /usr/sbin/groupadd -p x -k groupadd

    At the command line, execute the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: A new audit.STIG.rules file is provided as a supplemental document that can be placed in /etc/audit/rules.d that contains all rules needed for auditd.

    Note: An older audit.STIG.rules may exist if the file exists and references older \"GEN\" SRG IDs. This file can be removed and replaced as necessary with an updated one.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000001'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']

  describe auditd do
    its('lines') { should include %r{-w /usr/sbin/useradd -p x -k useradd} }
    its('lines') { should include %r{-w /usr/sbin/groupadd -p x -k groupadd} }
  end
end
