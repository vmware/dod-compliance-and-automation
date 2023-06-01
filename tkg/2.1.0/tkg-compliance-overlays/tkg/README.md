# TKG Compliance Overlays
**Note**: this has only been tested on aws. The ciphers used for STIG are FIPS approved(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) + AWS health check chiper(TLS_RSA_WITH_AES_256_GCM_SHA384). If the AWS cipher is removed it should only run with FIPS on vSphere but has not been tested. The FIPS approved ciphers do not allign with the STIG test so that control will fail.

The folder `04_user_customizations` contains scripts and ytt overlays to harden TKG for either STIG or CIS compliance. Its contents need to be placed in `$HOME/.config/tanzu/tkg/providers/ytt/04_user_customizations` 

The following env variables need to be added to your cluster configuration for tkg. 


| Env Vars| Options|
|---------|--------|
|COMPLIANCE|String: stig or cis|
|ENABLE_COMPLIANCE_SERVING_CERTS| boolean: true or false|
|PROTECT_KERNEL_DEFAULTS| boolean: true or false|

Compliance Serving Certs currently requires some manual steps after enabling as it requires a kubelet restart after serving certs are generated and approved. I am not sure the affect this will have in the event of a node restart as the Management Cluster will put back in the original configs.

The xlsx files in this repo are the output of a vanilla TKG build with two columns added that explain if this control is resolved by the overlays and an explanation of why they can or can not be resolved.

# STIG
To enable STIG Compliance set COMPLIANCE equal to stig in your clusterconfig for tkg.

# CIS
To enable CIS Compliance set COMPLIANCE equal to cis in your clusterconfig for tkg.
## EventRateLimit Admission Control Config
In order to edit the Event Rate Limit set at both the user and Namespace Level you will need to edit the yaml file defined in the function `def event_rate_conf` which is in `cis-overlay.yaml`

## Encryption Provider Config
By default the overlay uses aescbc encrytpion and generates a random key using the `set-encryption-conf.sh` script. If this needs to be changed you would need to modify the function `def encryption_conf` in `cis-overlay.yaml` to use an encrytpion type of your choice. Also in `cis-overlay.yaml` the preKubeAdmCommands section from line 47 to 49 would need to be deleted as well as the mounting of the `set-encryption-conf.sh` script from line 69 to 73.



# Enabling Server Certs
As mentioned in the overview compliance serving certs requires some manual steps after the fact. In order to enable Server Certs for either the STIG or CIS compliance set ENABLE_COMPLIANCE_SERVING_CERTS to true in your clusterconfig for tkg.

This will enable kubelet-certificate-authority on the api-server and set it equal to the kubernetes ca.crt file. The feature gate for RotateKubeletServerCertificate will be enabled on both the kubelet as well as on the controller-manager. Additionally it will set the client-ca-file on the kubelet, which is set by default in cis but not in the STIG, equal to the kubernetes ca.crt file. Finally it will enable rotate-server-certificates on the kubelet. 

Kubelet Serving Certificates are not auto approved hence the manual steps. To confirm that the cluster is not fucntioning before the approval you can attempt to run this kubectl command:
```sh
kubectl logs -l component=kube-apiserver -n kube-system
```

 They can not be auto approved without a custom controller. In order to approve the certs run the below command:
```sh
kubectl certificate approve $(kubectl get csr | grep Pending | grep 'kubernetes.io/kubelet-serving' | awk '{print $1}' | tr '\r\n' ' ')
```

After all of the certs are approved all of the kubectl commands will begin running. If you run the the same command that you ran prior to the approval you can confirm this:

```sh
kubectl logs -l component=kube-apiserver -n kube-system
```

 In the event a new node is added to the cluster the approval command will need to be run again

## Enabling tls-cert-file and tls-private-key-file
If you would like to add in --tls-cert-file and --tls-private-key-file which are both required as part of the STIG and CIS you can ssh into each node of the cluster now that the serving certs have been approved.


This can be done by running the below and replacing the variables in \<\> with your own values:
```sh
ssh -A -i <path to ssh key used to create tkg cluster> ubuntu@<bastion-host public ip>
ssh <private/internal ip of node>
```

 Once on the host Modify the  `/var/lib/kubelet/kubeadm-flags.env` file and add in the flags: `--tls-cert-file=/var/lib/kubelet/pki/kubelet-server-current.pem` and `--tls-private-key-file=/var/lib/kubelet/pki/kubelet-server-current.pem`. Then the kubelet will need to be restart with a `systemctl daemon-reload && systemctl restart kubelet`. To ensure it is running after the restart run `systemctl status kubelet`

 The above  will need to be run against each node in the cluster.

 In the event a new node is added to the cluster you will need to ssh into the new host and repeat the above after approving the csr. If a node is deleted and recreated it is likely the same will be the case as the state of the nodes kubelet config is stored within tkg's crd objects and will be restored to its original state.

# Protect Kernel Defaults

To enable protect-kernel-defaults on the kubelet the following flag needs to be set to true PROTECT_KERNEL_DEFAULTS. It is important to note that this flag can only be used with amis that have the kernel set up properly. The amis can be created using this repo for [stigs](https://gitlab.eng.vmware.com/tanzu-compliance/canonical-ubuntu-18.04-stigd-capi-image-builder) or this one for [cis](https://gitlab.eng.vmware.com/tanzu-compliance/canonical-ubuntu-18.04-cis-capi-image-builder).

# Assistance

For assistance on automation or spinning up a cluster reach out on #tanzu-rd-compliance in slack
