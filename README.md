# Cloud Run `tcpdump` sidecar

This repository contains the source code to create a container image containing `tcpdump` and `pcap-cli` to perform packet capture in [Cloud Run multi-container](https://cloud.google.com/logging/docs/structured-logging) deployments.

Captured packets are optionally translated to JSON and written into [`Cloud Logging`](https://cloud.google.com/logging/docs/structured-logging)

![alt text](https://github.com/gchux/cloud-run-tcpdump/blob/main/img/pcap.png?raw=true)

## Motivation

During development, it is often useful to perform packet capturing to troubleshoot specific/gnarly network related conditions/issues.

This container image is to be used as a sidecar of the Cloud Run main –*ingress*– container in order to perform a packet capture using `tcpdump` within the same network namespace.

The sidecar approach enables decoupling from the main –*ingress*– container so that it does not require any modifications to perform a packet capture; additionally, sidecars use their own resources which allows `tcpdump` to not compete with the main app resources allocation.

> **NOTE**: the main –*ingress*– container is the one to which all ingress traffic ( HTTP Requests ) is delivered to; for Cloud Run services, this is typically your APP container.

## Building blocks

- [Ubuntu 22.04 official docker image](https://hub.docker.com/_/ubuntu)
- [`tcpdump`](https://www.tcpdump.org/) installed from [Ubuntu's official repository](https://packages.ubuntu.com/search?keywords=tcpdump) to perform packet captures.
- [`gopacket`](https://github.com/google/gopacket/tree/master) to perform packet capturing and getting a handle on all captured packets.
- [GCSFuse](https://github.com/GoogleCloudPlatform/gcsfuse) to mount the GCS Bucket used to export **PCAP files**.
- [Go Supervisord](https://github.com/ochinchina/supervisord) to orchestrate startup processes execution.
- [fsnotify](https://github.com/fsnotify/fsnotify) to listen for filesystem events.
- [gocron](https://github.com/go-co-op/gocron) to schedule execution of `tcpdump`.
- [Docker Engine](https://docs.docker.com/engine/) and [Docker CLI](https://docs.docker.com/engine/reference/commandline/cli/) to build the sidecar container image.
- [Cloud Run](https://cloud.google.com/run/docs/deploying#multicontainer-yaml) **gen2** [execution environment](https://cloud.google.com/run/docs/about-execution-environments).
- [pcap-cli](https://github.com/gchux/pcap-cli/tree/main) to perform packet capturing and translations to JSON.

## How it works

The sidecar uses:

-    **`tcpdump`**/**`pcap-cli`** to capture packets in both wireshark compatible format and `JSON`. All containers use the same network namespace and so this sidecar captures packets from all containers within the same instance.

-    [**`pcap-cli`**](https://github.com/gchux/pcap-cli) allows to perform packet translations into [Cloud Logging compatible structured `JSON`](https://cloud.google.com/logging/docs/structured-logging). It also provides `HTTP/1.1` and `HTTP/2` analysis, including [Trace context](https://cloud.google.com/trace/docs/trace-context) awareness (`X-Cloud-Trace-Context`/`traceparenmt`) to hydrate structured logging with trace information which allows rich network data analysis using [Cloud Trace](https://cloud.google.com/trace/docs/overview).

-    [**`tcpdumpw`**](tcpdumpw/main.go) to execute `tcpdump`/[`pcap-cli`](https://github.com/gchux/pcap-cli) and generate **PCAP files**; optionally, schedules `tcpdump`/`pcap-cli` executions.

-    [**`pcap-fsnotify`**](pcap-fsnotify/main.go) to listen for newly created **PCAP files**, optionally compress PCAPs ( _**recommended**_ ) and move them into Cloud Storage mount point.

-    **GCSFuse** to mount a Cloud Storage Bucket to move compressed **PCAP files** into.

     >    **PCAP files** are moved from the sidecar's in-memory filesystem into the mounted Cloud Storage Bucket.

## How to build the sidecar

1. Define the `PROJECT_ID` environment variable; i/e: `export PROJECT_ID='...'`.

2. Clone this repository: 

     ```sh
     git clone --depth=1 --branch=main --single-branch https://github.com/gchux/cloud-run-tcpdump.git
     ```

> [!TIP]
> If you prefer to let Cloud Build perform all the tasks, go directly to build [using Cloud Build](#using-cloud-build)

3. Move into the repository local directory: `cd cloud-run-tcpdump`.

Continue with one of the following alternatives:

### Using a local environment or [Cloud Shell](https://cloud.google.com/shell/docs/launching-cloud-shell)

4. Build and push the `tcpdump` sidecar container image:

     ```sh
     export TCPDUMP_IMAGE_URI='...' # this is usually Artifact Registry
     ./docker_build ${TCPDUMP_IMAGE_URI}
     docker push ${TCPDUMP_IMAGE_URI}
     ```

### Using [Cloud Build](https://cloud.google.com/build/docs/build-config-file-schema)

This approach assumes that Artifact Registry is available in `PROJECT_ID`.

> If you skipped step (2), clone the [**gcb** branch](https://github.com/gchux/cloud-run-tcpdump/tree/gcb):
>
> ```sh
> git clone --depth=1 --branch=gcb --single-branch https://github.com/gchux/cloud-run-tcpdump.git
> ```

4. Define the following environment variables:

     ```sh
     export REPO_LOCATION='...' # Artifact Registry Docker repository location
     export REPO_NAME='...' # Artifact Registry Docker repository name
     export IMAGE_NAME='...' # container image name; i/e: `sidecars/tcpdump` 
     export IMAGE_TAG='...' # container image version; i/e: `latest`
     export TCPDUMP_IMAGE_URI="${REPO_LOCATION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${IMAGE_NAME}:${IMAGE_TAG}" # using Artifact Registry
     ```

5. Build and push the `tcpdump` sidecar container image using Cloud Build: 

     ```sh
     gcloud builds submit \
       --project=${PROJECT_ID} \
       --config=$(pwd)/cloudbuild.yaml \
       --substitutions='_REPO_LOCATION=${REPO_LOCATION},_REPO_NAME=${REPO_NAME},_IMAGE_NAME=${IMAGE_NAME},_IMAGE_TAG=${IMAGE_TAG}' $(pwd)
     ```

>    See the full list of available flags for `gcloud builds submit`: https://cloud.google.com/sdk/gcloud/reference/builds/submit

## Pulling the pre-built image

1. Start by setting the following environment variables:

     ```sh
     export PROJECT_ID='...' # GCP Project ID
     export REPO_LOCATION='...' # Artifact Registry Docker repository location
     export REPO_NAME='...' # Artifact Registry Docker repository name
     export IMAGE_NAME='...' # container image name; i/e: `sidecars/tcpdump` 
     export IMAGE_TAG='...' # container image version; i/e: `latest`
     export TCPDUMP_IMAGE_URI="${REPO_LOCATION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${IMAGE_NAME}:${IMAGE_TAG}" # using Artifact Registry
     ```

1. Next run the following Docker commands to pull the image, tag it, and push it to Artifact Registry:

     ```sh
     docker pull ghcr.io/gchux/cloud-run-tcpdump:latest
     docker tag ghcr.io/gchux/cloud-run-tcpdump:latest ${TCPDUMP_IMAGE_URI}
     docker push ${TCPDUMP_IMAGE_URI}
     ```

## How to deploy to Cloud Run

1. Define environment variables to be used during Cloud Run service deployment:

     ```sh
     export SERVICE_NAME='...'           # Cloud Run or App Engine Flex service name
     export SERVICE_REGION='...'         # GCP Region: https://cloud.google.com/about/locations
     export SERVICE_ACCOUNT='...'        # Cloud Run service's identity
     export INGRESS_CONTAINER_NAME='...' # the name of the ingress container i/e: `app`
     export INGRESS_IMAGE_URI='...'
     export INGRESS_PORT='...'
     export TCPDUMP_SIDECAR_NAME='...'
     export TCPDUMP_IMAGE_URI='...'      # same as the one used to build the sidecar container image
     export PCAP_IFACE='eth'             # prefix of the interface in which packets should be captured from
     export PCAP_GCS_BUCKET='...'        # the name of the Cloud Storage Bucket to mount
     export PCAP_FILTER='...'            # the BPF filter to use; i/e: `tcp port 443`
     export PCAP_JSON_LOG=true           # set to `true` for writting structured logs into Cloud Logging         
     ```

2. Deploy the Cloud Run service including the `tcpdump` sidecar:

> [!NOTE]  
> If adding the `tcpdump` sidecar to a preexisting Cloud Run service that is a single container service the gcloud command will fail. You will need to instead make these updates via the Cloud Console or create a new Cloud Run service.

     ```sh
     gcloud run deploy ${SERVICE_NAME} \
       --project=${PROJECT_ID} \
       --region=${SERVICE_REGION} \
       --execution-environment=gen2 \ # execution environment gen2 is mandatory
       --service-account=${SERVICE_ACCOUNT} \
       --container=${INGRESS_CONTAINER_NAME} \
       --image=${INGRESS_IMAGE_URI} \
       --port=${INGRESS_PORT} \
       --container=${TCPDUMP_SIDECAR_NAME} \
       --image=${TCPDUMP_IMAGE_URI} \
       --cpu=1 --memory=1G \
       --set-env-vars="PCAP_IFACE=${PCAP_IFACE},PCAP_GCS_BUCKET=${PCAP_GCS_BUCKET},PCAP_FILTER=${PCAP_FILTER},PCAP_JSON_LOG=${PCAP_JSON_LOG} \
     ```

>    See the full list of available flags for `gcloud run deploy` at https://cloud.google.com/sdk/gcloud/reference/run/deploy

3. All containers need to depend on the `tcpdump` sidecar, but this configuration is not available via gcloud due to needing to configure healthchecks for the sidecar container. To make all containers depend on the `tcpdump` sidecar, edit the Cloud Run service via the Cloud Console and make all other containers depend on the `tcpdump` sidecar and add the following TCP startup probe healthcheck to the `tcpdump` sidecar:

```
startupProbe:
 timeoutSeconds: 1
 periodSeconds: 10
 failureThreshold: 10
 tcpSocket:
   port: 12345
```

>    You can optionally choose a different port by setting `PCAP_HC_PORT` as an env var of the `tcpdump` sidecar

## Available configurations

The `tcpdump` sidecar accespts the following environment variables:

-    `PCAP_IFACE`: (STRING, **required**) a prefix for the interface to perform packet capturing on; i/e: `eth`, `ens`... 

     >    Notice that `PCAP_IFACE` is not the full interface name nor a regex or a pattern, but a prefix; so `eth0` becomes `eth`, and `ens4` becomes `ens`

-    `PCAP_GCS_BUCKET`: (STRING, **required**) the name of the Cloud Storage Bucket to be mounted and used to store **PCAP files**. Ensure that you provide the runtime service account the `roles/storage.admin` so that it may create objects and read bucket metadata.

-    `PCAP_FILTER`: (STRING, **required**) standard `tcpdump` bpf filters to scope the packet capture to specific traffic; i/e: `tcp`.

-    `PCAP_SNAPSHOT_LENGTH`: (NUMBER, *optional*) bytes of data from each packet rather than the default of 262144 bytes; default value is `0`. See https://www.tcpdump.org/manpages/tcpdump.1.html#:~:text=%2D%2D-,snapshot%2Dlength,-%3Dsnaplen

-    `PCAP_ROTATE_SECS`: (NUMBER, *optional*) how often to rotate **PCAP files** created by `tcpdump`; default value is `60` seconds.

-    `GCS_MOUNT`: (STRING, *optional*) where in the sidecar in-memory filesystem to mount the Cloud Storage Bucket; default value is `/pcap`.

-    `PCAP_FILE_EXT`: (STRING, *optional*) extension to be used for **PCAP files**; default value is `pcap`.

-    `PCAP_COMPRESS`: (BOOLEAN, *optional*) whether to compress **PCAP files** or not; default value is `true`.

-    `PCAP_TCPDUMP`: (BOOLEAN, *required*) whether to use `tcpdump` or not ( `tcpdump` will generate pcap files, if not `PCAP_JSON` must be enabled ) and push thos `.pcap` files to GCS; default valie is `true`.

-    `PCAP_JSON`: (BOOLEAN, *optional*) whether to use `JSON` to dump packets or not into GCS ; default value is `false`.

     >    `PCAP_TCPDUMP` and `PCAP_JSON` maybe be both `true` in order to generate both: `.pcap` and `.json` **PCAP files** that are stored in GCS.

-    `PCAP_JSON_LOG`: (BOOLEAN, *optional*) wheter to write `JSON` translated packets into `stdout` ( `PCAP_JSON` may not be enabled ); default value is `false`.

     >    This is useful when [`Wireshark`](https://www.wireshark.org/) is not available, as it makes it possible to have all captured packets available in [**Cloud Logging**](https://cloud.google.com/logging/docs/structured-logging)

-    `PCAP_ORDERED`: (BOOLEAN, *optional*) when `PCAP_JSON` or `PCAP_JSON_LOG` are enabled, wheter to print packets in captured order ( if set to `false`, packet will be written as fast as possible ); default value is `false`.

     >    In order to improve performance, packets are translated and written concurrently; when `PCAP_ORDERED` is enabled, only translations are performed concurrently. Enabling `PCAP_ORDERED` may cause packet capturing to be slower, so it is recommended to keep it disabled as all translated packets have a `pcap.num` property to assert order.

-    `PCAP_HC_PORT`: (NUMBER, *optional*) the TCP port that should be used to accept startup probes; connections will only be accepted when packet capturing is ready; default value is `12345`.

### Advanced configurations

More advanced use cases may benefit from scheduling `tcpdump` executions. Use the following environment variables to configure scheduling:

-    `PCAP_USE_CRON`: (BOOLEAN, *optional*) whether to enable scheduling of `tcpdump` executions; default value is `false`.

-    `PCAP_CRON_EXP`: (STRING, *optional*) [`cron` expression](https://man7.org/linux/man-pages/man5/crontab.5.html) used to configure scheduling `tcpdump` executions. 
     
     - **NOTE**: if `PCAP_USE_CRON` is set to `true`, then `PCAP_CRON_EXP` is required. See https://crontab.cronhub.io/ to get help with `crontab` expressions.

-    `PCAP_TIMEZONE`: (STRING, *optional*) the Timezone ID used to configure scheduling of `tcpdump` executions using `PCAP_CRON_EXP`; default value is `UTC`.

-    `PCAP_TIMEOUT_SECS`: (NUMBER, *optional*) seconds `tcpdump` execution will last; devault value is `0`: execution will not be stopped.

     >    **NOTE**: if `PCAP_USE_CRON` is set to `true`, you should set this value to less than the time in seconds between scheduled executions.

## Considerations

-    The Cloud Storage Bucket mounted by the `tcpdump` sidecar is not accessible by the main –ingress– container.

-    Processes running in the `tcpdump` sidecar are not visible to the main –*ingress*– container ( or any other container ); similarly, the `tcpdump` sidecar doesn't have visibility of processes running in other containers.

-    Packet capturing using `tcpdump` requires raw sockets, which is only available for Cloud Run **gen2** execution environment as it offers [full Linux compatibility](https://cloud.google.com/run/docs/about-execution-environments#:~:text=second%20generation%20execution%20environment%20provides%20full%20Linux%20compatibility).

-    All **PCAP files** will be stored within the Cloud Storage Bucket with the following "*hierarchy*": `PROJECT_ID`/`SERVICE_NAME`/`GCP_REGION`/`REVISION_NAME`/`INSTANCE_STARTUP_TIMESTAMP`/`INSTANCE_ID`.

     > this hierarchy guarantees that **PCAP files** are easily indexable and hard to override by multiple deployments/instances. It also simplifies deleting no longer needed PCAPs from specific deployments/instances.

-    When defining `PCAP_ROTATE_SECS`, keep in mind that the current **PCAP file** is temporarily stored in the sidecar in-memory filesystem. This means that if your APP is network intensive:

     -    The longer it takes to rotate the current **PCAP file**, the larger the current **PCAP file** will be, so...
         
     -    Larger **PCAP files** will require more memory to temporarily store the current one before offloading it into the Cloud Storage Bucket.

-    When defining `PCAP_SNAPSHOT_LENGTH`, keep in mind that a large value will result in larget **PCAP files**; additionally, you may not need to ispect the data, just the packet headers.

-    Keep in mind that every Cloud Run instance will produce its own set of **PCAP files**, so for troubleshooting purposes, it is best to define a low Cloud Run [maximum number of instances](https://cloud.google.com/run/docs/configuring/max-instances).

     > It is equally important to define a well scoped BPF filter in order to capture only the required packets and skip everything else. The `tcpdump` flag [--snapshot-length](https://www.tcpdump.org/manpages/tcpdump.1.html) is also useful to limit the bytes of data to capture from each packet.

-    Packet capturing is always on while the instance is available, so it is best to rollback to a non packet capturing revision and delete the packet-capturing one after you have captured all the required traffic.

-    The full packet capture from a Cloud Run instance will be composed out of multiple smaller ( optionally compressed ) **PCAP files**. Use a tool like [mergecap](https://www.wireshark.org/docs/man-pages/mergecap.html) to combine them into one.

-    In order to be able to mount the Cloud Storage Bucket and store **PCAP files**, [Cloud Run's identity](https://cloud.google.com/run/docs/securing/service-identity) must have proper [roles/permissions](https://cloud.google.com/storage/docs/access-control/iam-permissions).

-    The `tcpdump` sidecar is intended to be used for troubleshooting purposes only. While the `tcpdump` sidecar has its own set of resources, storing bytes from **PCAP files** in Cloud Storage introduces additional costs ( for both Storage and Networking ).

     -    Set `PCAP_COMPRESS` to `true` to store compressed **PCAP files** and save storage bytes; additionally, use regional Buckets to minize costs.

     -    Whenever possible, use packet capturing scheduling to avoid running `tcpdump` 100% of instance lifetime.

     -    When troubleshooting is complete, deploy a new Revision without the `tcpdump` sidecar to completely disable it.

-    While it is true that [Cloud Storage volume mounts](https://cloud.google.com/run/docs/configuring/services/cloud-storage-volume-mounts) is available in prevew, GCSFuse is used instead to minimize the required configuration to deploy a Revision instrumented with the `tcpdump` sidecar.

     >    **NOTE***: this is also the reason why the base image for the `tcpdump` sidecar is `ubuntu:22.04` and not something lighter like `alpine`. GCSFuse pre-built packages are only available for Debian and RPM based distributions.

-    While setting `PCAP_ORDER` to `true` is a good alternative for low traffic scenarios, it is recommended setting it to `false` for most other cases since the level of concurrency is reduced (only for translations) in order to guarantee packet order.

     >    **NOTE**: packet order means the order in which the underlying engine ([`gopacket`](https://github.com/google/gopacket)) delivers captured packets.

-    Use scheduled packet capturing ( `PCAP_USE_CRON` and other advanced flags ) if you don't need to capture packets 100% of instance runtime as it will reduce the number of `PCAP files`.

     >    **NOTE**: this sidecar is subject to [Cloud Run CPU allocation](https://cloud.google.com/run/docs/configuring/cpu-allocation) configuration; so if the revision is configured to only allocate CPU during request processing, then CPU will also be throttled for the sidecar. This means that when CPU is only allocated during request processing, no packet capturing will happen outside request processing; the same applies for `PCAP files` export into Cloud Storage.

## Download and Merge all PCAP Files

1. Use Cloud Logging to look for the entry starting with: `[INFO] - PCAP files available at: gs://`...

     It may be useful to use the following filter:

     ```
     resource.type = "cloud_run_revision"
     resource.labels.service_name = "<cloud-run-service-name>"
     resource.labels.location = "<cloud-run-service-region>"
     "<cloud-run-revision-name>"
     "PCAP files available at:"
     ```

     This entry contains the exact Cloud Storate path to be used to download all the **PCAP files**.

     Copy the full path including the prefix `gs://`, and assign it to the environment variable `GCS_PCAP_PATH`.

2. Download all **PCAP files** using:


     ```sh
     mkdir pcap_files
     cd  pcap_files
     gcloud storage cp ${GCS_PCAP_PATH}/*.gz . # use `${GCS_PCAP_PATH}/*.pcap` if `PCAP_COMPRESS` was set to `false`
     ```

3. If `PCAP_COMPRESS` was set to `true`, uncompress all the **PCAP files**: `gunzip ./*.gz`

4. Merge all **PCAP files** into a single file: 

    -    for `.pcap` files: `mergecap -w full.pcap -F pcap ./*_part_*.pcap`

    -    for `.json` files: `cat *_part_*.json | jq -crMs 'sort_by(.pcap.date)' > pcap.json`

    >    See `mergecap` docs: https://www.wireshark.org/docs/man-pages/mergecap.html

    >    See `jq` docs: https://jqlang.github.io/jq/manual/ , JSON pcaps are particularly useful when Wireshark is not available.

---

# Using with App Engine Flexible

1.    Enable debug mode an App Engine Flexible instance: https://cloud.google.com/appengine/docs/flexible/debugging-an-instance#enabling_and_disabling_debug_mode

2.    Connect to the instnace using SSH: https://cloud.google.com/appengine/docs/flexible/debugging-an-instance#connecting_to_the_instance

3.    Escalate privileges; execute: `sudo su`

4.    Create the following `env` file named `pcap.env`, use the following sample to define sidecar variables:

       ```sh
       # $ touch pcap.env
       PCAP_GAE=true
       PCAP_GCS_BUCKET=the-gcs-bucket    # the name of the Cloud Storage bucket used to store PCAP files
       GCS_MOUNT=/gae/pcap               # where to mount the Cloud Storage bucket within the container FS
       PCAP_IFACE=eth                    # network interface prefix
       PCAP_FILTER=tcp or udp            # BPF filter to scope packet capturing to specific network traffic
       PCAP_SNAPSHOT_LENGTH=0
       PCAP_USE_CRON=false               # do not schedule packet capturing
       PCAP_TIMEZONE=America/Los_Angeles
       PCAP_TIMEOUT_SECS=60
       PCAP_ROTATE_SECS=30
       PCAP_TCPDUMP=true
       PCAP_JSON=true
       PCAP_JSON_LOG=false               # NOT necessary, packet translations are streamed directly to Cloud Logging
       PCAP_ORDERED=false
       ```

5.    Create a directory to store the **PCAP files** in the host filesystem: `mkdir gae`

6.    Pull the sidecar container image: `docker --config=/etc/docker pull ${TCPDUMP_IMAGE_URI}`

7.    Run the sidecar to start capturing packets:

      ```sh
      docker run --rm --name=pcap -it \
        --cpus=1 --cpuset-cpus=1 \
        --privileged --network=host \
        --env-file=./pcap.env \
        -v ./gae:/gae -v /var/log:/var/log \
        -v /var/run/docker.sock:/docker.sock \
        ${TCPDUMP_IMAGE_URI} nsenter -t 1 -u -n -i /init \
        >/var/log/app_engine/app/STDOUT_pcap.log \
        2>/var/log/app_engine/app/STDERR_pcap.log
      ```

> **NOTE**: for **GAE Flex**: it is strongly recommended to not use `PCAP_FILTER=tcp or udp` ( or even `tcp port 443` ) as packets are streamed into Cloud Logging using its gRPC API, which means that traffic is HTTP/2 over TCP and so if you capture all TCP and UDP traffic you'll also be capturing all what's being exported into Cloud Logging which will cause a write aplification effect that will starve memory as all your traffic will eventually be stored in sidecar's memory.
