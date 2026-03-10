control 'UBTU-22-651025' do
  title 'Ubuntu 22.04 LTS must be configured so that the script that runs each 30 days or less to check file integrity is the default.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to Ubuntu 22.04 LTS performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify that the Advanced Intrusion Detection Environment (AIDE) default script used to check file integrity each 30 days or less is unchanged.

Download the original aide-common package in the /tmp directory:

     $ cd /tmp; apt download aide-common

Fetch the SHA1 of the original script file:

     $ dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum
     b71bb2cafaedf15ec3ac2f566f209d3260a37af0  -

Compare with the SHA1 of the file in the daily or monthly cron directory:

     $ sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null
     b71bb2cafaedf15ec3ac2f566f209d3260a37af0  /etc/cron.daily/aide

If there is no AIDE script file in the cron directories, or the SHA1 value of at least one file in the daily or monthly cron directory does not match the SHA1 of the original, this is a finding.'
  desc 'fix', 'The cron file for AIDE is fairly complex as it creates the report. This file is installed with the "aide-common" package, and the default can be restored by copying it from the package:

Extract the aide script from the "aide-common" package to its original place:

     $ dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | sudo tar -x ./usr/share/aide/config/cron.daily/aide -C /

Copy it to the cron.daily directory:

     $  sudo cp -f /usr/share/aide/config/cron.daily/aide /etc/cron.daily/aide'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64314r953566_chk'
  tag severity: 'medium'
  tag gid: 'V-260585'
  tag rid: 'SV-260585r958946_rule'
  tag stig_id: 'UBTU-22-651025'
  tag gtitle: 'SRG-OS-000446-GPOS-00200'
  tag fix_id: 'F-64222r953567_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']

  describe('Verify that the Advanced Intrusion Detection Environment (AIDE) default script used to check file integrity each 30 days or less is unchanged.') do
    skip('manual test')
  end
end
