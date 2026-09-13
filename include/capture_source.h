#ifndef CAPTURE_SOURCE_H
#define CAPTURE_SOURCE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "pcap_reader.h"

namespace DPI {

// A single raw packet handed from a capture source to the DPI pipeline.
// Mirrors PacketAnalyzer::RawPacket so parsing stays identical for
// file and live sources.
struct CapturePacket {
    PacketAnalyzer::PcapPacketHeader header;
    std::vector<uint8_t> data;
};

// ============================================================================
// CaptureSource - abstraction over where packets come from
// ============================================================================
//
// Two implementations:
//   FileCapture  - reads a saved .pcap file (existing PcapReader)
//   LiveCapture  - captures from a live interface via libpcap
//
// readNextPacket() semantics:
//   - returns false when the source is exhausted / has a fatal error
//   - for live sources returns true even on capture timeouts, with an
//     empty `data` vector (loop keeps polling until told to stop)
// ============================================================================
class CaptureSource {
public:
    virtual ~CaptureSource() = default;

    // Open the source. target = filename (file) or interface name (live).
    virtual bool open(const std::string& target, std::string& error) = 0;

    // Read the next packet. false = EOF (file) or fatal error (live).
    virtual bool readNextPacket(CapturePacket& packet) = 0;

    virtual bool isLive() const = 0;
    virtual const std::string& name() const = 0;

    // Global header to write to an output pcap (nullptr if none).
    virtual const PacketAnalyzer::PcapGlobalHeader* globalHeader() const {
        return nullptr;
    }
};

// Read packets from a saved .pcap file
class FileCapture : public CaptureSource {
public:
    bool open(const std::string& filename, std::string& error) override;
    bool readNextPacket(CapturePacket& packet) override;
    bool isLive() const override { return false; }
    const std::string& name() const override { return name_; }
    const PacketAnalyzer::PcapGlobalHeader* globalHeader() const override;

private:
    PacketAnalyzer::PcapReader reader_;
    std::string name_;
    PacketAnalyzer::PcapGlobalHeader global_header_;
};

// Live capture via libpcap. When built without HAVE_LIBPCAP the open()
// call reports a clear error instead of failing silently.
class LiveCapture : public CaptureSource {
public:
    LiveCapture() = default;
    ~LiveCapture() override;

    bool open(const std::string& interface, std::string& error) override;
    bool readNextPacket(CapturePacket& packet) override;
    bool isLive() const override { return true; }
    const std::string& name() const override { return name_; }
    const PacketAnalyzer::PcapGlobalHeader* globalHeader() const override;

    // List names of available capture interfaces (empty if unavailable).
    static std::vector<std::string> listInterfaces();

private:
    void* handle_ = nullptr;  // pcap_t* (opaque to keep header clean)
    std::string name_;
    PacketAnalyzer::PcapGlobalHeader global_header_;
    bool fatal_error_ = false;
};

} // namespace DPI

#endif // CAPTURE_SOURCE_H