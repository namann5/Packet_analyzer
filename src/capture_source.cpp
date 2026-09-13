#include "capture_source.h"

#include <iostream>

#ifdef HAVE_LIBPCAP
#include <pcap/pcap.h>
#endif

namespace DPI {

// ============================================================================
// FileCapture
// ============================================================================

bool FileCapture::open(const std::string& filename, std::string& error) {
    if (!reader_.open(filename)) {
        error = "Cannot open pcap file: " + filename;
        return false;
    }
    name_ = filename;
    global_header_ = reader_.getGlobalHeader();
    return true;
}

bool FileCapture::readNextPacket(CapturePacket& packet) {
    PacketAnalyzer::RawPacket raw;
    if (!reader_.readNextPacket(raw)) {
        return false;  // End of file
    }
    packet.header = raw.header;
    packet.data = std::move(raw.data);
    return true;
}

const PacketAnalyzer::PcapGlobalHeader* FileCapture::globalHeader() const {
    return &global_header_;
}

// ============================================================================
// LiveCapture
// ============================================================================

LiveCapture::~LiveCapture() {
#ifdef HAVE_LIBPCAP
    if (handle_) {
        pcap_close(static_cast<pcap_t*>(handle_));
        handle_ = nullptr;
    }
#endif
}

bool LiveCapture::open(const std::string& interface, std::string& error) {
#ifdef HAVE_LIBPCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_live(
        interface.c_str(),
        65535,     // snaplen
        1,         // promiscuous
        100,       // read timeout (ms)
        errbuf);

    if (!p) {
        error = "pcap_open_live(" + interface + ") failed: " + std::string(errbuf);
        return false;
    }

    handle_ = p;
    name_ = interface;
    fatal_error_ = false;

    // Build a synthetic pcap global header for optional output writing.
    global_header_.magic_number = 0xa1b2c3d4;
    global_header_.version_major = 2;
    global_header_.version_minor = 4;
    global_header_.thiszone = 0;
    global_header_.sigfigs = 0;
    global_header_.snaplen = 65535;
    global_header_.network = static_cast<uint32_t>(pcap_datalink(p));

    pcap_setnonblock(p, 1, errbuf);
    return true;
#else
    error = "Live capture requires libpcap. Rebuild with -Dlive_capture=true "
            "(Linux: install libpcap-dev; Windows: Npcap SDK).";
    (void)interface;
    return false;
#endif
}

bool LiveCapture::readNextPacket(CapturePacket& packet) {
#ifdef HAVE_LIBPCAP
    if (!handle_) {
        return false;
    }

    pcap_t* p = static_cast<pcap_t*>(handle_);
    struct pcap_pkthdr* hdr = nullptr;
    const u_char* data = nullptr;

    int rc = pcap_next_ex(p, &hdr, &data);
    if (rc == 1) {
        packet.header.ts_sec = hdr->ts.tv_sec;
        packet.header.ts_usec = hdr->ts.tv_usec;
        packet.header.incl_len = hdr->caplen;
        packet.header.orig_len = hdr->len;
        packet.data.assign(data, data + hdr->caplen);
        return true;
    }
    if (rc == 0) {
        // Timeout - no packet yet. Signal caller to keep polling.
        packet.data.clear();
        return true;
    }
    // rc == -1 (error) or -2 (savefile EOF): stop the capture loop.
    return false;
#else
    (void)packet;
    return false;
#endif
}

const PacketAnalyzer::PcapGlobalHeader* LiveCapture::globalHeader() const {
#ifdef HAVE_LIBPCAP
    if (handle_) {
        return &global_header_;
    }
#endif
    return nullptr;
}

std::vector<std::string> LiveCapture::listInterfaces() {
    std::vector<std::string> result;
#ifdef HAVE_LIBPCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return result;
    }
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if ((dev->flags & PCAP_IF_LOOPBACK) == 0 && dev->name != nullptr) {
            result.emplace_back(dev->name);
        }
    }
    pcap_freealldevs(alldevs);
#endif
    return result;
}

} // namespace DPI