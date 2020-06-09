package asset

// DefaultImages are the defualt images bootkube components use.
var DefaultImages = ImageVersions{
	Etcd:            "quay.io/coreos/etcd:v3.3.12",
	Flannel:         "quay.io/coreos/flannel:v0.11.0-amd64",
	FlannelCNI:      "quay.io/coreos/flannel-cni:v0.3.0",
	Calico:          "quay.io/calico/node:v3.0.3",
	CalicoCNI:       "quay.io/calico/cni:v2.0.0",
	CoreDNS:         "k8s.gcr.io/coredns:1.6.5",
	PodCheckpointer: "quay.io/coreos/pod-checkpointer:83e25e5968391b9eb342042c435d1b3eeddb2be1",

	Kubelet:               "docker.io/autonomy/kubelet:v1.19.0-beta.1",
	KubeAPIServer:         "k8s.gcr.io/kube-apiserver:v1.19.0-beta.1",
	KubeControllerManager: "k8s.gcr.io/kube-controller-manager:v1.19.0-beta.1",
	KubeProxy:             "k8s.gcr.io/kube-proxy:v1.19.0-beta.1",
	KubeScheduler:         "k8s.gcr.io/kube-scheduler:v1.19.0-beta.1",
}
