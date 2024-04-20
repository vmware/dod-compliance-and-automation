include_controls 'kubernetes' do
  # VMware Aria Automation Kubernetes is not externally managed
  skip_control 'CNTR-K8-000460'
  skip_control 'CNTR-K8-001160'
  skip_control 'CNTR-K8-001300'
  skip_control 'CNTR-K8-001400'
  skip_control 'CNTR-K8-001420'
  skip_control 'CNTR-K8-001460'
  skip_control 'CNTR-K8-001470'
  skip_control 'CNTR-K8-003220'

  # Handled by Photon audit policy
  skip_control 'CNTR-K8-000700'

  # Not Applicable
  skip_control 'CNTR-K8-000330'
  skip_control 'CNTR-K8-000420'
  skip_control 'CNTR-K8-000430'
  skip_control 'CNTR-K8-000440'
  skip_control 'CNTR-K8-000450'
end
