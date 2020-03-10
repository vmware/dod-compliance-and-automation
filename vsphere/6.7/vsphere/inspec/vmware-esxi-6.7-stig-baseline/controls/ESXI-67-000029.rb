control "ESXI-67-000029" do
  title "The ESXi host must remove keys from the SSH authorized_keys file."
  desc  "ESXi hosts come with SSH which can be enabled to allow remote access
without requiring user authentication. To enable password free access
copy the remote users public key into the
\"/etc/ssh/keys-root/authorized_keys\" file on the ESXi host. The
presence of the remote user's public key in the \"authorized_keys\" file
identifies the user as trusted, meaning the user is granted access to the host
without providing a password. If using Lockdown Mode and SSH is
disabled then login with authorized keys will have the same restrictions as
username/password."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000029"
  tag stig_id: "ESXI-67-000029"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From an SSH session connected to the ESXi host, or from the ESXi
shell, run the following command:

# ls -la /etc/ssh/keys-root/authorized_keys

or

# cat /etc/ssh/keys-root/authorized_keys

If the authorized_keys file exists and is not empty, this is a finding."
  desc 'fix', "From an SSH session connected to the ESXi host, or from the ESXi
shell, zero or remove the /etc/ssh/keys-root/authorized_keys file:

# >/etc/ssh/keys-root/authorized_keys

or

# rm /etc/ssh/keys-root/authorized_keys"

  describe "" do
    skip 'Manual verification is required for this control'
  end

#This is the powershell way to check this...not sure how to handle this yet in Inspec

#$results = Invoke-WebRequest -uri "https://$($vmhost.name)/host/ssh_root_authorized_keys" -Method Get -Credential $esxicred
#            If($results.Content.length -gt 1)

end

