# Cloud Run `tcpdump` sidecar

This repository contains the source code to create a container image containing `tcpdump` to perform packet capture in Cloud Run multi-container deployments.

## Motivation

During development, it is often useful to perform packet capture to troubleshoot specific network related issues/conditions.

This container image is to be used as a sidecar of the Cloud Run ingress container in order to perform a packet capture using `tcpdump` within the same network namespace.

The sidecar approach enables decoupling from the main –*ingress*– container so that it does not require any modifications to perform a packet capture; additionally, sidecars use their own resources which allows `tcpdump` to not compete with the main app resources allocation.

## Building blocks

- [Ubuntu 22.04 official docker image](https://hub.docker.com/_/ubuntu)
- [`tcpdump`](https://www.tcpdump.org/) installed from [Ubuntu's official repository](https://packages.ubuntu.com/search?keywords=tcpdump)
- [GCSFuse](https://github.com/GoogleCloudPlatform/gcsfuse)
- [fsnotify](https://github.com/fsnotify/fsnotify)
- [Docker Engine](https://docs.docker.com/engine/) and [Docker CLI](https://docs.docker.com/engine/reference/commandline/cli/) to build the sidecar container image
- [Cloud Run](https://cloud.google.com/run/docs/deploying#multicontainer-yaml) **gen2** [execution environment](https://cloud.google.com/run/docs/about-execution-environments)

## How it works

The sidecar uses:

-    **`tcpdump`** to capture packets. All containers use the same network namestap and so this sidecar captures packets from all containers within the same deployment.

-    [**`pcap-fsnotify`**](pcap-fsnotify/main.go) to listen for newly created **PCAP files**, optionally compress PCAPs ( _**recommended**_ ) and move them into Cloud Storate mount point.

-    **GCSFuse** to mount a Cloud Storage Bucket to move compressed **PCAP files** into.

     > **PCAP files** are moved from the sidecar's in-memory filesystem into the mounted Cloud Storage Bucket.

## How to build the sidecar

### Using a local environment or [Cloud Shell](https://cloud.google.com/shell/docs/launching-cloud-shell)

```sh
export TCPDUMP_IMAGE_URI='...' # this is usually Artifact Registry

git clone https://github.com/gchux/cloud-run-tcpdump.git

cd cloud-run-tcpdump
./docker_build ${TCPDUMP_IMAGE_URI}
docker push ${TCPDUMP_IMAGE_URI}
```

### Using [Cloud Build](https://cloud.google.com/build/docs/build-config-file-schema)

... TBD ...

## How to deploy to Cloud Run

1. Define environment variables to be used during Cloud Run service deployment:

     ```sh
     export PROJECT_ID='...' # GCP Project Id hosting the Cloud Run service
     export SERVICE_NAME='...'
     export SERVICE_REGION='...' # GCP Region: https://cloud.google.com/about/locations
     export SERVICE_ACCOUNT='...' # Cloud Run service's identity
     export INGRESS_CONTAINER_NAME='...'
     export INGRESS_IMAGE_URI='...'
     export INGRESS_PORT='...'
     export TCPDUMP_SIDECAR_NAME='...'
     export TCPDUMP_IMAGE_URI='...' # same as the one used to build the sidecar container image
     export GCS_BUCKET='...'        # the name of the Cloud Storage Bucket to mount
     export PCAP_FILTER='...'       # the BPF filter to use; i/e: `tcp port 443`
     export PCAP_ROTATE_SECS='...'  # how often to rocate PCAP files; default is `60` seconds 
     ```

2. Deploy the Cloud Run service including the `tcpdump` sidecar:

     ```sh
     gcloud beta run deploy ${SERVICE_NAME} \
       --project=${PROJECT_ID} \
       --region=${SERVICE_REGION} \
       --execution-environment=gen2 \ # execution environment gen2 is mandatory
       --service-account=${SERVICE_ACCOUNT} \
       --container=${INGRESS_CONTAINER_NAME}-1 \
       --image=${INGRESS_IMAGE_URI} \
       --port=${INGRESS_PORT} \
       --container=${TCPDUMP_SIDECAR_NAME}-1 \
       --image=${TCPDUMP_IMAGE_URI} \
       --cpu=1 --memory=1G \
       --set-env-vars="GCS_BUCKET=${GCS_BUCKET},PCAP_FILTER=${PCAP_FILTER},PCAP_ROTATE_SECS=${PCAP_ROTATE_SECS}" \
       --depends-on=${INGRESS_CONTAINER_NAME}-1
     ```

> See the full list of available falgs for `gcloud run deplot` at https://cloud.google.com/sdk/gcloud/reference/run/deploy

## Available configurations

The `tcpdump` sidecar accespts the following environment variables:

-    `GCS_BUCKET`: (string, required) the name of the Cloud Storage Bucket to be mounted and used to store **PCAP files**.
-    `PCAP_FILTER`: (string required) standard `tcpdump` bpf filters to scope the packet capture to specific traffic; i/e: `tcp`.
-    `PCAP_FLAGS`: (string, optional) [flags](https://www.tcpdump.org/manpages/tcpdump.1.html) to be passed to `tcpdump`; default value is `-n -s 0`.
-    `PCAP_ROTATE_SECS`: (number, optional) how often to rotate **PCAP files** created by `tcpdump`; default value is `60` seconds.
-    `GCS_MOUNT`: (string, optional) where in the sidecar in-memory filesystem to mount the Cloud Storage Bucket; default value is `/pcap`.
-    `PCAP_FILE_EXT`: (string, optional) extension to be used for **PCAP files**; default value is `pcap`.
-    `PCAP_COMPRESS`: (boolean, optional) whether to compress **PCAP files** or not; default value is `true`.

## Considerations

-    Packet capturing using `tcpdump` requires raw sockets, which is only available for Cloud Run **gen2** execution environment as it offers [full Linux compatibility](https://cloud.google.com/run/docs/about-execution-environments#:~:text=second%20generation%20execution%20environment%20provides%20full%20Linux%20compatibility).

-    All **PCAP files** will be stored within the Cloud Storage Bucket with the following "hierarchy": `PROJECT_ID`/`SERVICE_NAME`/`GCP_REGION`/`REVISION_NAME`/`DEPLOYMENT_DATETIME`/`INSTANCE_ID`.

     > this hierarchy guarantees that **PCAP files** are easily indexable and hard to override by multiple deployments/instances. It also simplifies deleting no longer needed PCAPs from specific deployments/instances.

-    When defining `PCAP_ROTATE_SECS`, keep in mind that the current PCAP file is temporarily stored in the sidecar in-memory filesystem. This means that if your APP is network intensive:

     -    The longer it takes to rotate the current PCAP file, the larger the current PCAP file will be, so...
         
     -    Larger **PCAP files** will require more memory to temporarily store the current one before offloading it into the Cloud Storage Bucket.

-    Keep in mind that every Cloud Run instance will produce its own set of **PCAP files**, so for troubleshooting purposes, it is best to define a low Cloud Run [maximum number of instances](https://cloud.google.com/run/docs/configuring/max-instances).

     > It is equally important to define a well scoped BPF filter in order to capture only the required packets and skip everything else. The `tcpdump` flag [--snapshot-length](https://www.tcpdump.org/manpages/tcpdump.1.html) is also useful to limit the bytes of data to capture from each packet.

-    Packet capturing is always on while the instance is available, so it is best to rollback to a non packet capturing revision and delete the packet-capturing one after you have captured all the required traffic.

-    The full packet capture from a Cloud Run instance will be composed out of multiple smaller ( optionally compressed ) **PCAP files**. Use a tool like [mergecap](https://www.wireshark.org/docs/man-pages/mergecap.html) or [joincap](https://github.com/assafmo/joincap) to combine them into one.

-    In order to be able to mount the Cloud Storage Bucket and store **PCAP files**, [Cloud Run's identity](https://cloud.google.com/run/docs/securing/service-identity) must have proper [roles/permissions](https://cloud.google.com/storage/docs/access-control/iam-permissions).
