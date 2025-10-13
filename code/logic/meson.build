dir = include_directories('.')
cc = meson.get_compiler('c')


fossil_ai_lib = library('fossil_ai',
    files('jellyfish.c', 'iochat.c', 'language.c'),
    install: true,
    dependencies: [cc.find_library('m', required: false)],
    include_directories: dir)

fossil_ai_dep = declare_dependency(
    link_with: [fossil_ai_lib],
    include_directories: dir)

meson.override_dependency('fossil-ai', fossil_ai_dep)
