# encoding: UTF-8

control 'PHTN-30-000054' do
  title "The Photon operating system must audit the execution of privileged
functions."
  desc  "Misuse of privileged functions, either intentionally or
unintentionally by authorized users, or by unauthorized external entities that
have compromised information system accounts, is a serious and ongoing concern
and can have significant adverse impacts on organizations. Auditing the use of
privileged functions is one way to detect such misuse and identify the risk
from insider threats and the advanced persistent threat."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command to see a list of setuid
files:

    # find / -xdev -perm -4000 -type f -o -perm -2000 -type f | sort

    Then, execute the following command for each setuid file found in the first
command:

    # auditctl -l | grep <setuid_path>

    Replace <setuid_path> with each path found in the first command.

    If each <setuid_path> does not have a corresponding line in the audit
rules, this is a finding.

    A typical corresponding line will look like the below:

    -a always,exit -F path=<setuid_path> -F perm=x -F auid>=1000 -F
auid!=4294967295 -F key=privileged
  "
  desc  'fix', "
    At the command line, execute the following command to see a list of setuid
files:

    # find / -xdev -perm -4000 -type f -o -perm -2000 -type f | sort

    Then, execute the following for each setuid file found in the first command
that does not have a corresponding line in the audit rules:

    Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the
following lines:

    -a always,exit -F path=<setuid_path> -F perm=x -F auid>=1000 -F
auid!=4294967295 -F key=privileged

    At the command line, execute the following command to load the new audit
rules.

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag stig_id: 'PHTN-30-000054'
  tag cci: 'CCI-002234'
  tag nist: ['AC-6 (9)']

  results = command('find / -xdev -perm -4000 -type f -o -perm -2000 -type f').stdout.split("\n")
  
  # results.each do | path |
  #   describe.one do
  #     describe command("grep #{path} /etc/audit/audit.rules") do
  #       its ('stdout.strip') {should match ("-a always,exit -F path=#{path} -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged")}
  #     end
  #     describe command("grep #{path} /etc/audit/audit.rules") do
  #       its ('stdout.strip') {should match ("-a exit,always -F path=#{path} -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged")}
  #     end
  #   end
  # end

  results.each do | path |
    describe.one do

      describe auditd do
        its("lines") { should include %r{-a always,exit -F path=#{path} -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged} }
      end
      describe auditd do
        its("lines") { should include %r{-a always,exit -S all -F path=#{path} -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged} }
      end

    end
  end

end

