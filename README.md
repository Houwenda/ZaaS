# ZaaS

ZaaS is short for Zeek as a Service.

ZaaS offers a restful API for Analyzer modules (part of my graduation project) to analyse specific (compressed) libpcap(.pcap) file saved in seaweedfs, which is protected by Basic Auth.

Once receiving an HTTP request on the secret endpoint, ZaaS tries retrieving the pcap file saved in seaweedfs via a Seaweedfs Filer behind an Nginx reverse proxy. (Currently Seaweedfs Filer does not support access control, so I use Nginx to provide basic authentication for it.)

If ZaaS successfully downloads the pcap file, it will check whether the file is compressed by TrafficCacher (another part of my graduation project) using zstd and decompress it if necessary.

Then ZaaS can use [Zeek](https://github.com/zeek/zeek) to perform DPI (Deep Packet Inspection), generating logs based on zeek configuration. Those logs can be collected by Filebeat and then sent to Elasticsearch for further analysis.

If any file is extracted and saved in the specific directory, ZaaS will send those files back into seaweedfs.

References: [blacktop/docker-zeek](https://github.com/blacktop/docker-zeek), [certego/zeek](https://github.com/certego/docker-zeek), [file-extraction](https://github.com/hosom/file-extraction/)

## Build
When building docker image, use the following command to make zaas binary compatible with alpine (blacktop/zeek) image.
```shellscript
CGO_ENABLED=0 go build .
```