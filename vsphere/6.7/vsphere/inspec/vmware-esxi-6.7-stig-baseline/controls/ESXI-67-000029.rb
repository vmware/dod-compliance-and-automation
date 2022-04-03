control 'ESXI-67-000029' do
  title 'The ESXi host must remove keys from the SSH authorized_keys file.'
  desc  "ESXi hosts come with SSH, which can be enabled to allow remote access
without requiring user authentication. To enable password-free access, copy the
remote user's public key into the \"/etc/ssh/keys-root/authorized_keys\" file
on the ESXi host.

    The presence of the remote user's public key in the \"authorized_keys\"
file identifies the user as trusted, meaning the user is granted access to the
host without providing a password.

    If using Lockdown Mode and SSH is disabled, then logon with authorized keys
will have the same restrictions as username/password.
  "
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # ls -la /etc/ssh/keys-root/authorized_keys

    or

    # cat /etc/ssh/keys-root/authorized_keys

    If the \"authorized_keys\" file exists and is not empty, this is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell,
zero out or remove the /etc/ssh/keys-root/authorized_keys file:

    # >/etc/ssh/keys-root/authorized_keys

    or

    # rm /etc/ssh/keys-root/authorized_keys
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239284'
  tag rid: 'SV-239284r674781_rule'
  tag stig_id: 'ESXI-67-000029'
  tag fix_id: 'F-42476r674780_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end

  # This is the powershell way to check this...not sure how to handle this yet in Inspec

  # $results = Invoke-WebRequest -uri "https://$($vmhost.name)/host/ssh_root_authorized_keys" -Method Get -Credential $esxicred
  #            If($results.Content.length -gt 1)
end
