control 'DKER-CE-000196' do
  title 'Docker CE must verify cgroup usage on containers.'
  desc  "
    It is possible to attach to a particular cgroup on container run. Confirming cgroup usage will ensure that containers are running under defined cgroups.

    System administrators typically define cgroups under which containers are supposed to run. Even if cgroups are not explicitly defined by the system administrators, containers run under docker cgroup by default. At run-time, it is possible to attach to a different cgroup than the one that was expected to be used. This usage must be monitored and confirmed. By attaching to a different cgroup than the one that is expected, excess permissions and resources might be granted to the container and thus can prove to be unsafe.

    By default, containers run under docker cgroup.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CgroupParent={{ .HostConfig.CgroupParent }}'

    If the CgroupParent is blank, the container is running under the default docker cgroupparent, this is NOT a finding.

    If a container has a cgroupparent defined and it is not the one documented in the SSP, this is a finding.
  "
  desc  'fix', "
    For containers returned by the check command do the following:

    Stop the container and then start the container without specifying the --cgroup-parent argument.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-DKER-CE-000196'
  tag rid: 'SV-DKER-CE-000196'
  tag stig_id: 'DKER-CE-000196'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
