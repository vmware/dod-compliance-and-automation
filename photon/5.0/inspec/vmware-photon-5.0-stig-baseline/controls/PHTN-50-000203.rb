control 'PHTN-50-000203' do
  title 'The Photon operating system must terminate idle Secure Shell (SSH) sessions.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i ClientAliveCountMax

    Expected result:

    clientalivecountmax 0

    If \"ClientAliveCountMax\" is not set to \"0\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"ClientAliveCountMax\" line is uncommented and set to the following:

    ClientAliveCountMax 0

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag gid: 'V-PHTN-50-000203'
  tag rid: 'SV-PHTN-50-000203'
  tag stig_id: 'PHTN-50-000203'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i ClientAliveCountMax") do
    its('stdout.strip') { should cmp 'ClientAliveCountMax 0' }
  end
end
