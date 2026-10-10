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
  'src/anomaly_detector.cpp',
  'src/blocklist.cpp',
  'src/vpn_detector.cpp',
  'src/events.cpp',
  'src/ipc_emitter.cpp',
)

extra_deps = []
if host_machine.system() == 'windows'
  extra_deps += meson.get_compiler('cpp').find_library('ws2_32', required: true)
endif

# ---------------------------------------------------------------------------
# Threads dependency (required for the multi-threaded fast-path engine)
# ---------------------------------------------------------------------------
thread_dep = dependency('threads')

# ---------------------------------------------------------------------------
# Optional: libpcap for live capture (Track A). Enabled via -Dlive_capture=true
# ---------------------------------------------------------------------------
# NOTE: do NOT put a bare disabler() into a target's dependencies - meson
# silently drops the entire target (and its tests) when a dependency is a
# disabler. Only append pcap_dep when libpcap is actually available.
live_capture = get_option('live_capture')
pcap_deps = []
pcap_include_dirs = []
if live_capture
  npcap_sdk = get_option('npcap_sdk')
  if npcap_sdk != '' and host_machine.system() == 'windows'
    add_project_arguments('-DHAVE_LIBPCAP', language: 'cpp')
    sdk_lib_dir = npcap_sdk / 'Lib' / (host_machine.cpu_family() == 'x86_64' ? 'x64' : 'x86')
    pcap_deps += [
      meson.get_compiler('cpp').find_library('wpcap', required: true, dirs: sdk_lib_dir),
      meson.get_compiler('cpp').find_library('ws2_32', required: true),
    ]
    pcap_include_dirs += include_directories(npcap_sdk / 'Include')
  else
    pcap_dep = dependency('libpcap', required: false)
    if pcap_dep.found()
      add_project_arguments('-DHAVE_LIBPCAP', language: 'cpp')
      pcap_deps += pcap_dep
    else
      warning('libpcap not found - building without live capture support')
      message('Install libpcap (Linux: libpcap-dev, Windows: Npcap SDK) to enable live capture')
    endif
  endif
endif

# Optional Windows platform dependencies (urlmon)
win_deps = []
if host_machine.system() == 'windows'
  win_deps += meson.get_compiler('cpp').find_library('urlmon', required: false)
endif

# ---------------------------------------------------------------------------
# DPI engine executable
# ---------------------------------------------------------------------------
engine_include_dirs = include_directories('include')
if pcap_include_dirs.length() > 0
  engine_include_dirs += pcap_include_dirs
endif

dpi_engine = executable(
  'dpi_engine',
  engine_sources,
  dependencies: [thread_dep] + pcap_deps + extra_deps + win_deps,
  include_directories: engine_include_dirs,
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
# Track B Unit & Integration test binary (only built when tests are enabled)
# ---------------------------------------------------------------------------
if get_option('tests')
  test_track_b = executable(
    'test_track_b',
    files(
      'src/test_track_b.cpp',
      'src/anomaly_detector.cpp',
      'src/blocklist.cpp',
      'src/vpn_detector.cpp',
      'src/events.cpp',
      'src/ipc_emitter.cpp',
      'src/types.cpp',
      'src/packet_parser.cpp',
    ),
    dependencies: [thread_dep] + win_deps,
    include_directories: include_directories('include'),
  )
endif

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
  # Absolute paths make all tests independent of meson test's working dir.
  test(
    'engine_smoke',
    dpi_engine,
    args: [
      meson.current_source_dir() / 'test_dpi.pcap',
      meson.current_build_dir() / 'output_test.pcap',
      '--block-app', 'YouTube',
    ],
    timeout: 30,
  )

  test(
    'rules_cli_persistence',
    dpi_cli,
    args: [
      'add-rule', '--type', 'domain', '--value', '*.example.com',
      '--store', meson.current_build_dir() / 'rules_test.json',
    ],
    timeout: 15,
  )

  test(
    'track_b_unit_tests',
    test_track_b,
    timeout: 30,
  )

  test(
    'security_smoke',
    dpi_engine,
    args: [
      meson.current_source_dir() / 'test_malicious.pcap',
      meson.current_build_dir() / 'output_malicious.pcap',
      '--block-vpn',
      '--urlhaus', meson.current_source_dir() / 'data' / 'urlhaus_test_sample.txt',
      '--vpn-ranges', meson.current_source_dir() / 'data' / 'vpn_ranges.json',
      '--events-out', meson.current_build_dir() / 'events_test.jsonl',
    ],
    timeout: 30,
  )

  py_mod = import('python')
  py_inst = py_mod.find_installation('python3', required: false)
  if not py_inst.found()
    py_inst = py_mod.find_installation('python', required: false)
  endif
  if py_inst.found()
    r = run_command(py_inst, '-c', 'import pytest', check: false)
    if r.returncode() == 0
      test(
        'dashboard_tests',
        py_inst,
        args: [
          '-m', 'pytest',
          meson.current_source_dir() / 'dashboard' / 'test_dashboard.py',
        ],
        timeout: 30,
      )
    endif
  endif
endif
