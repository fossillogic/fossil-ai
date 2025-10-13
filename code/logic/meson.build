dir = include_directories('.')
cc = meson.get_compiler('c')
add_project_arguments('-D_POSIX_C_SOURCE=200112L', language: 'c')
add_project_arguments('-D_POSIX_C_SOURCE=200112L', language: 'cpp')

# Check if the host system is Windows
if host_machine.system() == 'windows'
    winsock_dep = cc.find_library('ws2_32', required: true)
else
    winsock_dep = []
endif

fossil_ai_lib = library('fossil_ai',
    files('jellyfish.c', 'iochat.c', 'language.c'),
    install: true,
    dependencies: [cc.find_library('m', required: false), winsock_dep],
    include_directories: dir)

fossil_ai_dep = declare_dependency(
    link_with: [fossil_ai_lib],
    include_directories: dir)

meson.override_dependency('fossil-ai', fossil_ai_dep)
