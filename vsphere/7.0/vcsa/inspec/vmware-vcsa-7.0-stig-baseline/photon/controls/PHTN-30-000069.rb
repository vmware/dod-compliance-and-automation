control 'PHTN-30-000069' do
  title 'The Photon operating system must audit the "insmod" module.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'At the command line, run the following command:

# auditctl -l | grep "/sbin/insmod"

Expected result:

-w /sbin/insmod -p x

If the output does not match the expected result, this is a finding.

Note: This check depends on the auditd service to be in a running state for accurate results. The auditd service is enabled in control PHTN-30-000013.'
  desc 'fix', 'Navigate to and open:

/etc/audit/rules.d/audit.STIG.rules

Add the following lines:

-w /sbin/insmod -p x

Execute the following command to load the new audit rules:

# /sbin/augenrules --load

Note: A new "audit.STIG.rules" file is provided for placement in "/etc/audit/rules.d" that contains all rules needed for auditd.

Note: An older "audit.STIG.rules" may exist if the file exists and references older "GEN" SRG IDs. This file can be removed and replaced as necessary with an updated one.'
  impact 0.5
  tag check_id: 'C-60214r887289_chk'
  tag severity: 'medium'
  tag gid: 'V-256539'
  tag rid: 'SV-256539r887291_rule'
  tag stig_id: 'PHTN-30-000069'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-60157r887290_fix'
  tag satisfies: ['SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd do
    its('lines') { should include %r{-w /sbin/insmod -p x} }
  end
end
