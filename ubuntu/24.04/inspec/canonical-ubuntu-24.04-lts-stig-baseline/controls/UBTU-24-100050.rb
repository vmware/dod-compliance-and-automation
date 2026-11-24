control 'UBTU-24-100050' do
  title 'Ubuntu 24.04 LTS must not have the nfs-kernel-server package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Note: If NFS mounts are authorized and in use on the system, this control is not applicable.

Verify that Ubuntu 24.04 LTS does not have the nfs-kernel-server package installed.

Determine if packages are installed:
$ sudo dpkg -l | grep -E \'nfs-kernel-server\'

If the nfs-kernel-server package is installed, this is a finding.'
  desc 'fix', 'Configure the Ubuntu 24.04 LTS operating system to disable nonessential capabilities by removing the nfs-kernel-server package from the system with the following commands:

Remove packages if present:
$ sudo apt purge --yes nfs-kernel-server

Remove any unneeded dependencies:
$ sudo apt autoremove --yes

Verify that NFS services are gone:
$ sudo systemctl list-units --type=service | grep nfs'
  impact 0.7
  tag check_id: 'C-84498r1261500_chk'
  tag severity: 'high'
  tag gid: 'V-279938'
  tag rid: 'SV-279938r1261502_rule'
  tag stig_id: 'UBTU-24-100050'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-84403r1261501_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe package('nfs-kernel-server') do
    it { should_not be_installed }
  end

  describe command('dpkg -l | grep nfs-kernel-server') do
    its('stdout') { should_not match(/rc/) }
  end
end
