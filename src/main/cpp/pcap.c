#include <pcap.h>

void pcap_fatal_error(const char *failed_in, const chat *errbuf) {
  printf("Fatal error in %s: %s\n", failed_in, err_buf);
}

int pcap_init(){
  struct pcap_pkthdr header;
  const u_char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *device;
  pcap_t *pcap_handle;
  int i;

  device = pcap_lookupdev(errbuf);
  if (device == NULL) {
    pcap_fatal("pcap_lookupdev", errbuf);
  }

  prtinf("starting with device %s\n", device);  
}
