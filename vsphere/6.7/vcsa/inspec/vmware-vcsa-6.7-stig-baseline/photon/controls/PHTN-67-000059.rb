control 'PHTN-67-000059' do
  title "The Photon operating system must configure a cron job to rotate auditd
logs daily."
  desc  "Audit logs are most useful when accessible by date, rather than size.
This can be accomplished through a combination of an audit log rotation cron
job, setting a reasonable number of logs to keep and configuring auditd to not
rotate the logs on its own. This ensures that audit logs are accessible to the
ISSO in the event of a central log processing failure."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # cat /etc/cron.daily/audit-rotate

    Expected result:

    #!/bin/bash
    service auditd rotate

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    If /etc/cron.daily/audit-rotate does not exist, run the following commands:

    # touch /etc/cron.daily/audit-rotate
    # chown root:root /etc/cron.daily/audit-rotate
    # chmod 0700 /etc/cron.daily/audit-rotate

    Open /etc/cron.daily/audit-rotate with a text editor.

    Set its contents as follows:

    #!/bin/bash
    service auditd rotate
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-239130'
  tag rid: 'SV-239130r675198_rule'
  tag stig_id: 'PHTN-67-000059'
  tag fix_id: 'F-42300r675197_fix'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe file('/etc/cron.daily/audit-rotate') do
    it { should exist }
    its('content') { should match %r{#!/bin/bash} }
    its('content') { should match /service auditd rotate/ }
  end
end
