control 'UBTU-22-412030' do
  title 'Ubuntu 22.04 LTS must automatically exit interactive command shell user sessions after 15 minutes of inactivity.'
  desc 'Terminating an idle interactive command shell user session within a short time period reduces the window of opportunity for unauthorized personnel to take control of it when left unattended in a virtual terminal or physical console.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to automatically exit interactive command shell user sessions after 15 minutes of inactivity or less by using the following command:

     $ sudo grep -E "\\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/*
     /etc/profile.d/99-terminal_tmout.sh:TMOUT=900

If "TMOUT" is not set to "900" or less, is set to "0", is commented out, or missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to exit interactive command shell user sessions after 15 minutes of inactivity.

Create and/or append a custom file under "/etc/profile.d/" by using the following command:

     $ sudo su -c "echo TMOUT=900 >> /etc/profile.d/99-terminal_tmout.sh"

This will set a timeout value of 15 minutes for all future sessions.

To set the timeout for the current sessions, execute the following command over the terminal session:

     $ export TMOUT=900'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64283r953473_chk'
  tag severity: 'medium'
  tag gid: 'V-260554'
  tag rid: 'SV-260554r958636_rule'
  tag stig_id: 'UBTU-22-412030'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-64191r953474_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']

  profile_files = command('find /etc/profile.d/ /etc/bash.bashrc -type f').stdout.strip.split("\n").entries
  timeout = input('tmout').to_s

  describe.one do
    profile_files.each do |pf|
      describe file(pf.strip) do
        its('content') { should match "^TMOUT=#{timeout}$" }
      end
    end
  end
end
