control 'PHTN-50-000069' do
  title 'The Photon operating system must terminate idle Secure Shell (SSH) sessions after 15 minutes.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i ClientAliveInterval

    Example result:

    ClientAliveInterval 900

    If there is no output or if \"ClientAliveInterval\" is not set to \"900\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"ClientAliveInterval\" line is uncommented and set to the following:

    ClientAliveInterval 900

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag satisfies: ['SRG-OS-000395-GPOS-00175']
  tag gid: 'V-PHTN-50-000069'
  tag rid: 'SV-PHTN-50-000069'
  tag stig_id: 'PHTN-50-000069'
  tag cci: ['CCI-001133', 'CCI-002891']
  tag nist: ['MA-4 (7)', 'SC-10']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i ClientAliveInterval") do
    its('stdout.strip') { should cmp 'ClientAliveInterval 900' }
  end
end
