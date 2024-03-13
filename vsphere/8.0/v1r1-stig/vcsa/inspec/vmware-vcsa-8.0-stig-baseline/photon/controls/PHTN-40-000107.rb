control 'PHTN-40-000107' do
  title 'The Photon operating system must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'At the command line, run the following command to output a list of files with setuid/setgid configured and their corresponding audit rules:

# for file in $(find / -xdev -path /var/lib/containerd -prune -o \\( -perm -4000 -o -perm -2000 \\) -type f -print | sort); do echo "Found file with setuid/setgid configured: $file";rule="$(auditctl -l | grep "$file ")";echo "Audit Rule Result: $rule";echo ""; done

Example output:

Found file with setuid/setgid configured: /usr/bin/chage
Audit Rule Result: -a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged

Found file with setuid/setgid configured: /usr/bin/chfn
Audit Rule Result: -a always,exit -S all -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged

If each file returned does not have a corresponding audit rule, this is a finding.

Note: This check depends on the "auditd" service to be in a running state for accurate results. The "auditd" service is enabled in control PHTN-40-000016.

Note: auid!=-1, auid!=4294967295, auid!=unset are functionally equivalent in this check and the output of the above commands may be displayed in either format.'
  desc 'fix', 'Run the following steps for each file found in the check that does not have a corresponding line in the audit rules:

Navigate to and open:

/etc/audit/rules.d/audit.STIG.rules

Add the following line:

-a always,exit -F path=<path> -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

Run the following command to load the new audit rules:

# /sbin/augenrules --load

Note: An "audit.STIG.rules" file is provided with this guidance for placement in "/etc/audit/rules.d" that contains all rules needed for auditd.

Note: An older "audit.STIG.rules" may exist and may reference older "GEN" SRG IDs. This file can be removed and replaced as necessary with an updated one.'
  impact 0.5
  tag check_id: 'C-62582r933585_chk'
  tag severity: 'medium'
  tag gid: 'V-258842'
  tag rid: 'SV-258842r933587_rule'
  tag stig_id: 'PHTN-40-000107'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-62491r933586_fix'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000471-GPOS-00215']
  tag cci: ['CCI-000172', 'CCI-001404', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-2 (4)', 'AC-6 (9)']

  results = command('find / -xdev -path /var/lib/containerd -prune -o \( -perm -4000 -type f -o -perm -2000 \) -type f -print').stdout.split("\n")
  if !results.empty?
    results.each do |path|
      describe auditd do
        # -S all is added to these after they are processed
        its('lines') { should include /-a always,exit -S all -F path=#{path} -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged/ }
      end
    end
  else
    describe 'No setuid files found troubleshoot command and rerun.' do
      skip 'No setuid files found troubleshoot command and rerun.'
    end
  end
end
