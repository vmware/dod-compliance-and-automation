control 'PHTN-50-000175' do
  title 'The Photon operating system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc  "
    Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify an audit rule exists to audit kernel modules:

    # auditctl -l | grep init_module

    Expected result:

    -a always,exit -F arch=b32 -S init_module -F key=modules
    -a always,exit -F arch=b64 -S init_module -F key=modules

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the \"auditd\" service to be in a running state for accurate results. The \"auditd\" service is enabled in control PHTN-50-000016.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add or update the following lines:

    -a always,exit -F arch=b32 -S init_module -F key=modules
    -a always,exit -F arch=b64 -S init_module -F key=modules

    At the command line, run the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: An \"audit.STIG.rules\" file is provided with this guidance for placement in \"/etc/audit/rules.d\" that contains all rules needed for auditd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag satisfies: ['SRG-OS-000477-GPOS-00222']
  tag gid: 'V-PHTN-50-000175'
  tag rid: 'SV-PHTN-50-000175'
  tag stig_id: 'PHTN-50-000175'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd do
    its('lines') { should include /-a always,exit -F arch=b32 -S init_module -F key=modules/ }
    its('lines') { should include /-a always,exit -F arch=b64 -S init_module -F key=modules/ }
  end
end
