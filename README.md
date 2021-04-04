#ZaaS
ZaaS is short for Zeek as a Service.

Offerring a restful API for Analyzer module to analyse specific (compressed) libpcap file(.pcap) saved in seaweedfs, which is protected by Basic Auth.

Once receiving an HTTP request on the secret endpoint, ZaaS tries retrieving the pcap file saved in seaweedfs via a Seaweedfs Filer behind an Nginx reverse proxy.

If ZaaS successfully downloads the pcap file, it will check if the file is compressed(by TrafficCacher, in the format of zstd) and decompress it.

Then ZaaS can use Zeek to perform Deep Packet Inspection(DPI), generating logs based on zeek configuration. The logs can be collected by Filebeat and sent to Elasticsearch.

If any file is extracted and saved in certain directory, ZaaS will also send those files back into seaweedfs. (Reference: [certego/zeek](github.com/certego/docker-zeek/))

## Build
When running in docker, use `CGO_ENABLED=0 go build .` to get compatible with alpine(blacktop/zeek) image.