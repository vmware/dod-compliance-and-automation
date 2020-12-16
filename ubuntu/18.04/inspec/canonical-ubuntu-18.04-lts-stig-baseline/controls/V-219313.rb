# encoding: UTF-8

control 'V-219313' do
  title "The Ubuntu operating system must use SSH to protect the
confidentiality and integrity of transmitted information unless otherwise
protected by alternative physical safeguards, such as, at a minimum, a
Protected Distribution System (PDS)."
  desc  "Without protection of the transmitted information, confidentiality and
integrity may be compromised because unprotected communications can be
intercepted and either read or altered.

    This requirement applies to both internal and external networks and all
types of information system components from which information can be
transmitted (e.g., servers, mobile devices, notebook computers, printers,
copiers, scanners, and facsimile machines). Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of
interception and modification.

    Protecting the confidentiality and integrity of organizational information
can be accomplished by physical means (e.g., employing physical distribution
systems) or by logical means (e.g., employing cryptographic techniques). If
physical means of protection are employed, then logical means (cryptography) do
not have to be employed, and vice versa.

    Alternative physical protection measures include PDS. PDSs are used to
transmit unencrypted classified National Security Information (NSI) through an
area of lesser classification or control. Since the classified NSI is
unencrypted, the PDS must provide adequate electrical, electromagnetic, and
physical safeguards to deter exploitation.


  "
  desc  'rationale', ''
  desc  'check', "
    Check that the ssh package is installed with the following command:

    # sudo dpkg -l | grep openssh
    ii openssh-client 1:7.6p1-4ubuntu0.1 amd64 secure shell (SSH) client, for
secure access to remote machines
    ii openssh-server 1:7.6p1-4ubuntu0.1 amd64 secure shell (SSH) server, for
secure access from remote machines
    ii openssh-sftp-server 1:7.6p1-4ubuntu0.1 amd64 secure shell (SSH) sftp
server module, for SFTP access from remote machines

    If the \"openssh\" server package is not installed, this is a finding.

    Check that the \"sshd.service\" is loaded and active with the following
command:

    # sudo systemctl status sshd.service | egrep -i \"(active|loaded)\"
     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset:
enabled)
     Active: active (running) since Thu 2019-01-24 22:52:58 UTC; 1 weeks 3 days
ago

    If \"sshd.service\" is not active or loaded, this is a finding.
  "
  desc  'fix', "
    Install the \"ssh\" meta-package on the system with the following command:

    # sudo apt install ssh

    Enable the \"ssh\" service to start automatically on reboot with the
following command:

    # sudo systemctl enable sshd.service

    Ensure that the \"ssh\" service is running.

    # sudo systemctl start sshd.service
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188',
'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag gid: 'V-219313'
  tag rid: 'SV-219313r508662_rule'
  tag stig_id: 'UBTU-18-010420'
  tag fix_id: 'F-21037r305268_fix'
  tag cci: ['V-100849', 'SV-109953', 'CCI-002418', 'CCI-002420', 'CCI-002421',
'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']

  describe package('openssh-server') do
    it { should be_installed }
  end

  describe service('sshd') do
    it { should be_enabled }
    it { should be_installed }
    it { should be_running }
  end
end

