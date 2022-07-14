control 'PHTN-30-000070' do
  title 'The Photon operating system auditd service must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc  "
    Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E /etc/security/opasswd

    If any of these are not listed with a permissions filter of at least \"w\", this is a finding.

    Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done in control PHTN-30-000013.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add the following line:

    -w /etc/security/opasswd -p wa -k opasswd

    Execute the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: A new audit.STIG.rules file is provided as a supplemental document that can be placed in /etc/audit/rules.d that contains all rules needed for auditd.

    Note: An older audit.STIG.rules may exist if the file exists and references older \"GEN\" SRG IDs. This file can be removed and replaced as necessary with an updated one.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000476-GPOS-00221'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000070'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd do
    its('lines') { should include %r{-w /etc/security/opasswd -p wa -k opasswd} }
  end
end
