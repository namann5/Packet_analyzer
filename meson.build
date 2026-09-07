project(
  'packet_analyzer',
  'cpp',
  version: '1.0.0',
  default_options: [
    'cpp_std=c++17',
    'warning_level=3',
    'buildtype=release',
  ],
)

# ---------------------------------------------------------------------------
# Core engine sources (modular architecture)
# ---------------------------------------------------------------------------
engine_sources = files(
  'src/main_dpi.cpp',
  'src/dpi_engine.cpp',
  'src/pcap_reader.cpp',
  'src/packet_parser.cpp',
  'src/sni_extractor.cpp',
  'src/types.cpp',
  'src/rule_manager.cpp',
  'src/connection_tracker.cpp',
  'src/load_balancer.cpp',
  'src/fast_path.cpp',
)

# ---------------------------------------------------------------------------
# Threads dependency (required for the multi-threaded fast-path engine)
# ---------------------------------------------------------------------------
thread_dep = dependency('threads')

# ---------------------------------------------------------------------------
# Optional: libpcap for live capture (Track A). Enabled via -Dlive_capture=true
# ---------------------------------------------------------------------------
live_capture = get_option('live_capture')
if live_capture
  pcap_dep = dependency('libpcap', required: false)
  if pcap_dep.found()
    add_project_arguments('-DHAVE_LIBPCAP', language: 'cpp')
  else
    warning('libpcap not found - building without live capture support')
    message('Install libpcap (Linux: libpcap-dev, Windows: Npcap SDK) to enable live capture')
  endif
endif

# ---------------------------------------------------------------------------
# DPI engine executable
# ---------------------------------------------------------------------------
dpi_engine = executable(
  'dpi_engine',
  engine_sources,
  dependencies: [thread_dep],
  include_directories: include_directories('include'),
  install: true,
)

# ---------------------------------------------------------------------------
# Simple packet viewer (baseline tool)
# ---------------------------------------------------------------------------
viewer_sources = files(
  'src/main.cpp',
  'src/pcap_reader.cpp',
  'src/packet_parser.cpp',
)

packet_analyzer = executable(
  'packet_analyzer',
  viewer_sources,
  include_directories: include_directories('include'),
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if meson.is_cross_build() == false and get_option('tests')
  test(
    'engine_smoke',
    dpi_engine,
    args: ['test_dpi.pcap', 'output_test.pcap', '--block-app', 'YouTube'],
    timeout: 30,
  )
endif
