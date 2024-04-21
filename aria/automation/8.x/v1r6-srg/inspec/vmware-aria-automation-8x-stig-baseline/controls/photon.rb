include_controls 'photon' do
  # SELinux not supported yet
  skip_control 'PHTN-40-000066'

  # AIDE package not available yet
  skip_control 'PHTN-40-000127'
  skip_control 'PHTN-40-000237'

  # Not configurable, other implementations exist
  skip_control 'PHTN-40-000013' # There OOB if fips selected during install, not configurable after install
  skip_control 'PHTN-40-000182' # There OOB if fips selected during install, not configurable after install
  skip_control 'PHTN-40-000245'

  # Rsyslogd is not present on the VMware Aria Automation appliances and other methods can be utilized instead to view ssh login events.
  skip_control 'PHTN-40-000012'
  skip_control 'PHTN-40-000074'
  skip_control 'PHTN-40-000111'
  skip_control 'PHTN-40-000241'
  skip_control 'PHTN-40-000242'

  # NTP configuration is handled in the VMware Aria Automation Application STIG Readiness Guide content.
  skip_control 'PHTN-40-000121'

  # The VMware Aria Automation appliances run Kubernetes/Docker to run containers that make up the services of VMware Aria Automation.
  # In order to properly route traffic between containers this kernel setting cannot be disabled.
  skip_control 'PHTN-40-000231'

  # Handled by VMware Aria Automation controls
  skip_control 'PHTN-40-000219' # VRAA-8X-000127
  skip_control 'PHTN-40-000236' # VRAA-8X-000128
end
