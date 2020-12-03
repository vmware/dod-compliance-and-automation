control 'V-219296' do
  title "The Ubuntu operating system must generate records for
    successful/unsuccessful uses of init_module or finit_module syscalls."
  desc  "Without generating audit records that are specific to the security and
    mission needs of the organization, it would be difficult to establish,
    correlate, and investigate the events relating to an incident or identify those
    responsible for one.

    Audit records can be generated from various components within the
    information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000477-GPOS-00222"
  tag "satisfies": nil
  tag "gid": 'V-219296'
  tag "rid": "SV-219296r381493_rule"
  tag "stig_id": "UBTU-18-010387"
  tag "fix_id": "F-21020r305217_fix"
  tag "cci": [ "CCI-000172" ]
  tag "nist": nil

  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify if the Ubuntu operating system is configured to audit the
    \"init_module\" and \"finit_module\" syscalls, by running the following command:

    # sudo auditctl -l | grep -E 'init_module|finit_module'

    -a always,exit -F arch=b64 -S init_module -S finit_module -F key=modules
    -a always,exit -F arch=b32 -S init_module -S finit_module -F key=modules

    If the command does not return lines that match the example or the lines are
    commented out, this is a finding.

    Notes:
    For 32-bit architectures, only the 32-bit specific output lines from the
    commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after it
    does not need to match the example output above.
  "
  desc 'fix', "Configure the audit system to generate an audit event for any use of
    the \"init_module\" or \"finit_module\" system calls.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

    -a always,exit -F arch=b32 -S init_module -S finit_module -F key=modules
    -a always,exit -F arch=b64 -S init_module -S finit_module -F key=modules

    Notes: For 32-bit architectures, only the 32-bit specific entries are required.
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  if os.arch == 'x86_64'
    describe auditd.syscall('init_module').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
  describe auditd.syscall('init_module').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
end
