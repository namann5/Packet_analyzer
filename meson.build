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
  'src/capture_source.cpp',
  'src/rules_store.cpp',
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
else
  pcap_dep = disabler()
endif

# ---------------------------------------------------------------------------
# DPI engine executable
# ---------------------------------------------------------------------------
dpi_engine = executable(
  'dpi_engine',
  engine_sources,
  dependencies: [thread_dep, pcap_dep],
  include_directories: include_directories('include'),
  install: true,
)

# ---------------------------------------------------------------------------
# Rules CLI (persistent rule management - Track A)
# ---------------------------------------------------------------------------
dpi_cli = executable(
  'dpi_cli',
  files('src/dpi_cli.cpp', 'src/rules_store.cpp', 'src/rule_manager.cpp', 'src/types.cpp'),
  dependencies: thread_dep,
  include_directories: include_directories('include'),
  install: true,
)

# ---------------------------------------------------------------------------
# Simple packet viewer (baseline tool)
# ---------------------------------------------------------------------------
packet_analyzer = executable(
  'packet_analyzer',
  files('src/main.cpp', 'src/pcap_reader.cpp', 'src/packet_parser.cpp'),
  include_directories: include_directories('include'),
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if get_option('tests')
  test(
    'engine_smoke',
    dpi_engine,
    args: ['test_dpi.pcap', 'output_test.pcap', '--block-app', 'YouTube'],
    timeout: 30,
  )

  test(
    'rules_cli_persistence',
    dpi_cli,
    args: ['add-rule', '--type', 'domain', '--value', '*.example.com', '--store', 'rules_test.json'],
    timeout: 15,
  )
endif