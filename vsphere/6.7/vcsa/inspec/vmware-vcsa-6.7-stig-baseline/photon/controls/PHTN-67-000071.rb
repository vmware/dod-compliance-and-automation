control 'PHTN-67-000071' do
  title "The Photon operating system must generate audit records when the sudo
command is used."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep sudo

    Expected result:

    -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=1 -k
privileged

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the auditd service to be in a running state for
accurate results. Enabling the auditd service is done as part of a separate
control.
  "
  desc 'fix', "
    Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the
following lines:

    -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged

    At the command line, execute the following command:

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000458-GPOS-00203'
  tag satisfies: ['SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207',
'SRG-OS-000466-GPOS-00210', 'SRG-OS-000468-GPOS-00212']
  tag gid: 'V-239142'
  tag rid: 'SV-239142r816643_rule'
  tag stig_id: 'PHTN-67-000071'
  tag fix_id: 'F-42312r816642_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd do
    its('lines') { should include %r{-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1} }
  end
end
