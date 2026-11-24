control 'UBTU-24-100120' do
  title 'Ubuntu 24.04 LTS must be configured so that the script which runs each 30 days or less to check file integrity is the default one.'
  desc 'Without verification, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to Ubuntu 24.04 LTS performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Note: If AIDE is not installed, this finding is not applicable.

Check the AIDE configuration file integrity installed on the system (the default configuration file is located at /etc/aide/aide.conf or in /etc/aide/aide.conf.d/) with the following command:
$ sudo sha256sum /etc/aide/aide.conf
f3bbea2552f2c5b475627850d8a5fba1659df6466986d5a18948d9821ecbe491  /etc/aide/aide.conf

Download the original aide-common package in the /tmp directory:
$ cd /tmp; apt download aide-common

Generate the checksum from the aide.conf file in the downloaded .deb package:
$ sudo dpkg-deb --fsys-tarfile /tmp/aide-common_0.18.6-2build2_all.deb | tar -xO ./usr/share/aide/config/aide/aide.conf | sha256sum
f3bbea2552f2c5b475627850d8a5fba1659df6466986d5a18948d9821ecbe491  -

If the checksums of the system file (/etc/aide/aide.conf) and the extracted file do not match, this is a finding.

To verify the frequency of the file integrity checks, inspect the contents of the scheduled jobs as follows:

Checking scheduled cron jobs:
$ grep -r aide /etc/cron* /etc/crontab
/etc/cron.daily/dailyaidecheck:SCRIPT="/usr/share/aide/bin/dailyaidecheck"

Checking the systemd timer (this will show when the next scheduled run occurs and the last time the AIDE check was triggered):
$ sudo systemctl list-timers | grep aide
Thu 2024-10-31 02:01:58 EDT           10h Wed 2024-10-30 13:47:41 EDT            - dailyaidecheck.timer           dailyaidecheck.service

The contents of these files can be inspected with the following commands:
$ sudo systemctl cat dailyaidecheck.timer
$ sudo systemctl cat dailyaidecheck.service

If there is no AIDE script file in the cron directories or in the systemd timer, this is a finding.'
  desc 'fix', 'The cron file for AIDE is fairly complex as it creates the report. This file is installed with the "aide-common" package, and the default can be restored by copying it from the package:

Download the original package to the /tmp dir:

$ cd /tmp; apt download aide-common

Extract the aide script to its original place:

$ dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | sudo tar -x --wildcards ./usr/share/aide/config/cron.daily/dailyaidecheck* -C /

Copy it to the cron.daily directory:

$  sudo cp -f /usr/share/aide/config/cron.daily/aide /etc/cron.daily/dailyaidecheck*'
  impact 0.5
  tag check_id: 'C-74684r1066440_chk'
  tag severity: 'medium'
  tag gid: 'V-270651'
  tag rid: 'SV-270651r1068395_rule'
  tag stig_id: 'UBTU-24-100120'
  tag gtitle: 'SRG-OS-000446-GPOS-00200'
  tag fix_id: 'F-74585r1068394_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']

  describe('Verify that the Advanced Intrusion Detection Environment (AIDE) default script used to check file integrity each 30 days or less is unchanged.') do
    skip('This is a manual review.')
  end
end
