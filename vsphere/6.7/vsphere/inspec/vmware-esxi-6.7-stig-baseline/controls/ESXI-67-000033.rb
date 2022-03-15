control 'ESXI-67-000033' do
  title "The password hashes stored on the ESXi host must have been generated
using a FIPS 140-2 approved cryptographic hashing algorithm."
  desc  "Systems must employ cryptographic hashes for passwords using the SHA-2
family of algorithms or FIPS 140-2 approved successors. The use of unapproved
algorithms may result in weak password hashes more vulnerable to compromise."
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # grep -i \"^password\" /etc/pam.d/passwd | grep sufficient

    If sha512 is not listed, this is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in “/etc/pam.d/passwd”:

    password sufficient /lib/security/$ISA/pam_unix.so use_authtok nullok
shadow sha512 remember=5
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239288'
  tag rid: 'SV-239288r674793_rule'
  tag stig_id: 'ESXI-67-000033'
  tag fix_id: 'F-42480r674792_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
