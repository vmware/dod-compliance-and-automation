control 'PHTN-30-000068' do
  title 'The Photon operating system must generate audit records when successful/unsuccessful logon attempts occur.'
  desc  "
    Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E \"faillog|lastlog|tallylog\"

    Expected result:

    -w /var/log/faillog -p wa
    -w /var/log/lastlog -p wa
    -w /var/log/tallylog -p wa

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done in control PHTN-30-000013.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add the following lines:

    -w /var/log/faillog -p wa
    -w /var/log/lastlog -p wa
    -w /var/log/tallylog -p wa

    Execute the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: A new audit.STIG.rules file is provided as a supplemental document that can be placed in /etc/audit/rules.d that contains all rules needed for auditd.

    Note: An older audit.STIG.rules may exist if the file exists and references older \"GEN\" SRG IDs. This file can be removed and replaced as necessary with an updated one.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag satisfies: ['SRG-OS-000473-GPOS-00218', 'SRG-OS-000472-GPOS-00217']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000068'
  tag cci: ['CCI-000172', 'CCI-000172', 'CCI-000172']
  tag nist: ['AU-12 c', 'AU-12 c', 'AU-12 c']

  describe auditd do
    its('lines') { should include %r{-w /var/log/faillog -p wa} }
    its('lines') { should include %r{-w /var/log/lastlog -p wa} }
    its('lines') { should include %r{-w /var/log/tallylog -p wa} }
  end
end
