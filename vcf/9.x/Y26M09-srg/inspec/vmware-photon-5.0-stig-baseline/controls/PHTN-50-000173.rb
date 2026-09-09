control 'PHTN-50-000173' do
  title 'The Photon operating system must generate audit records when successful/unsuccessful logon attempts occur.'
  desc  "
    Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify an audit rule exists to audit logon attempts:

    # auditctl -l | grep -E \"faillog|lastlog|tallylog\"

    Expected result:

    -w /var/log/faillog -p wa -k logons
    -w /var/log/lastlog -p wa -k logons
    -w /var/log/tallylog -p wa -k logons

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the \"auditd\" service to be in a running state for accurate results. The \"auditd\" service is enabled in control PHTN-50-000016.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add or update the following lines:

    -w /var/log/faillog -p wa -k logons
    -w /var/log/lastlog -p wa -k logons
    -w /var/log/tallylog -p wa -k logons

    At the command line, run the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: An \"audit.STIG.rules\" file is provided with this guidance for placement in \"/etc/audit/rules.d\" that contains all rules needed for auditd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag gid: 'V-PHTN-50-000173'
  tag rid: 'SV-PHTN-50-000173'
  tag stig_id: 'PHTN-50-000173'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd.file('/var/log/faillog') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'logons' }
  end
  describe auditd.file('/var/log/lastlog') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'logons' }
  end
  describe auditd.file('/var/log/tallylog') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'logons' }
  end
end
