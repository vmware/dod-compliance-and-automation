control 'UBTU-22-651015' do
  title 'Ubuntu 22.04 LTS must configure AIDE to perform file integrity checking on the file system.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to Ubuntu 22.04 LTS performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify that Advanced Intrusion Detection Environment (AIDE) is configured and operating correctly by using the following command (this will take a few minutes):

Note: If AIDE is not installed, this requirement is not applicable.

     $ sudo aide -c /etc/aide/aide.conf --check

Example output:

Start timestamp: 2024-04-01 04:20:00 +1300 (AIDE 0.17.4)
AIDE found differences between database and filesystem!!
Ignored e2fs attributes: EIh
...

If AIDE is being used to perform file integrity checks but the command fails, this is a finding.'
  desc 'fix', 'Initialize AIDE (this will take a few minutes):

     $ sudo aideinit
     Running aide --init...

Example output:

Start timestamp: 2024-04-01 04:20:00 +1300 (AIDE 0.17.4)
AIDE initialized database at /var/lib/aide/aide.db.new
Ignored e2fs attributes: EIh

Number of entries:      146185

---------------------------------------------------
The attributes of the (uncompressed) database(s):
---------------------------------------------------

/var/lib/aide/aide.db.new
 SHA256    : UrYbC/KBOJcs8zKcSlKoifnnoPK66DEC
             Aw6odu/BpgY=
 SHA512    : ezENbbuh937SPWvtsdjRzy3i47XjLg7j
             L3UGmr0EcgY6u8rczxgbn2RuwJfrIpef
             0c1qMNobzrLXyDnnqEqAqw==
 RMD160    : yBq2xio+g5ne4kvZzzMZ2v+EO9w=
 TIGER     : GkJ/xkzJGu/aSQqk9A5LN271IOAQC3d0
 CRC32     : g/beXA==
 HAVAL     : zZm220YZiGna2edJ6Gi0rPv16AlpqeHB
             y/XLB3hIPEY=
 WHIRLPOOL : k6veoXavJ/BH9L125pCYAfTB8w5ZJkdC
             DvVmYS0+cgmg7M0y/S2v42FNCEJ993mc
             3kZMXJR/VVmwKg/7ntGixQ==
 GOST      : psjiyix6mJlNsE984D0NwbfgBmB0ETGl
             /R4PNvm/wKg=

End timestamp: 2024-04-01 04:29:16 +1300 (run time: 9m 16s)'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64312r953560_chk'
  tag severity: 'medium'
  tag gid: 'V-260583'
  tag rid: 'SV-260583r958944_rule'
  tag stig_id: 'UBTU-22-651015'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-64220r953561_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']

  describe command('aide -c /etc/aide/aide.conf --check') do
    its('stdout.strip') { should match /AIDE found/ }
    its('stdout.strip') { should_not match /Couldn't open file/ }
  end
end
