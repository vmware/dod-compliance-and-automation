control 'PHTN-30-000054' do
  title 'The Photon operating system must audit the execution of privileged functions.'
  desc  'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command to obtain a list of setuid files:

    # find / -xdev -perm -4000 -type f -o -perm -2000 -type f | sort

    Execute the following command for each setuid file found in the first command:

    # auditctl -l | grep <setuid_path>

    Replace <setuid_path> with each path found in the first command.

    If each <setuid_path> does not have a corresponding line in the audit rules, this is a finding.

    A typical corresponding line will look like the below:

    -a always,exit -F path=<setuid_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged

    Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done in control PHTN-30-000013.
  "
  desc 'fix', "
    At the command line, execute the following command to obtain a list of setuid files:

    # find / -xdev -perm -4000 -type f -o -perm -2000 -type f | sort

    Execute the following for each setuid file found in the first command that does not have a corresponding line in the audit rules:

    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add the following line:

    -a always,exit -F path=<setuid_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged

    Execute the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: A new audit.STIG.rules file is provided as a supplemental document that can be placed in /etc/audit/rules.d that contains all rules needed for auditd.

    Note: An older audit.STIG.rules may exist if the file exists and references older \"GEN\" SRG IDs. This file can be removed and replaced as necessary with an updated one.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag satisfies: ['SRG-OS-000471-GPOS-00215']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000054'
  tag cci: ['CCI-002234', 'CCI-000172']
  tag nist: ['AC-6 (9)', 'AU-12 c']

  results = command('find / -xdev -perm -4000 -type f -o -perm -2000 -type f').stdout.split("\n")
  results.each do |path|
    describe.one do
      describe auditd do
        its('lines') { should include %r{-a always,exit -F path=#{path} -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged} }
      end
      describe auditd do
        its('lines') { should include %r{-a always,exit -S all -F path=#{path} -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged} }
      end
    end
  end
end
