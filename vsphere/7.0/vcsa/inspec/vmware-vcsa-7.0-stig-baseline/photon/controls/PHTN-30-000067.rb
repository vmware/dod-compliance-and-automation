# encoding: UTF-8

control 'PHTN-30-000067' do
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
    -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged

    If the output does not match the expected result, this is a finding.

    Note: The auid!= parameter may display as 4294967295 or -1 which are equivalent.

    Note: This check depends on the auditd service to be in a running state for 
    accurate results. Enabling the auditd service is done in control PHTN-30-000013.
  "
  desc  'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add the following line:

    -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F
auid!=4294967295 -F key=privileged

    Execute the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: An older audit.STIG.rules may exist if the file exists and references 
    older \"GEN\" SRG IDs. This file can be removed and replaced as necessary 
    with an updated one.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000458-GPOS-00203'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000067'
  tag fix_id: nil
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  
  describe.one do

    describe auditd do
      its("lines") { should include %r{-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged} }
    end
    describe auditd do
      its("lines") { should include %r{-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged} }
    end

  end

end

