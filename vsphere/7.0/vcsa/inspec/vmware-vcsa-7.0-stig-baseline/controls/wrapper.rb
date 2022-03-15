include_controls 'eam'
include_controls 'lookup'
include_controls 'perfcharts'
include_controls 'photon' do
  # VCSA currently cannot implement this control so it must be skipped.
  skip_control 'PHTN-30-000049'
end
include_controls 'postgres'
include_controls 'rhttpproxy'
include_controls 'sts'
include_controls 'vami'
include_controls 'vsphere-ui'
