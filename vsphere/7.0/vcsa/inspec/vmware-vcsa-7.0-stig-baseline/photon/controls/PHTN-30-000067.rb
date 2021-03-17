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
  "
  desc  'fix', "
    Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the
following lines:

    -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F
auid!=4294967295 -F key=privileged

    At the command line, execute the following command to load the new audit
rules.

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000458-GPOS-00203'
  tag stig_id: 'PHTN-30-000067'
  tag cci: 'CCI-000172'
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

