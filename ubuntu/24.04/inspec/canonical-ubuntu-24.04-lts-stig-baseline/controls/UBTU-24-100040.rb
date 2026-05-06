control 'UBTU-24-100040' do
  title 'Ubuntu 24.04 LTS must not have the rsh-server package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Verify the rsh-server package is installed with the following command:

$ dpkg -l | grep rsh-server

If the rsh-server package is installed, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to disable nonessential capabilities by removing the rsh-server package from the system with the following command:

$ sudo apt remove rsh-server'
  impact 0.7
  tag check_id: 'C-74681r1066431_chk'
  tag severity: 'high'
  tag gid: 'V-270648'
  tag rid: 'SV-270648r1066433_rule'
  tag stig_id: 'UBTU-24-100040'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-74582r1066432_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe package('rsh-server') do
    it { should_not be_installed }
  end
end
