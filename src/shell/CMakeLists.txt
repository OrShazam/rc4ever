enable_language(ASM_MASM)

add_library(shell)

target_compile_definitions(shell PRIVATE -D_UNICODE -DUNICODE)

set(HEADER_PATH ${PROJECT_SOURCE_DIR}/include/shell)

target_include_directories(shell PUBLIC ${HEADER_PATH})

target_sources(shell
    PUBLIC
        ${HEADER_PATH}/install_shell.h
    PRIVATE
        install_shell.c
        entry_export.h
)

    target_sources(shell
        PRIVATE
            entry_x64.asm
    )

    set_source_files_properties(entry_x64.asm PROPERTIES COMPILE_FLAGS "/c")
    set_source_files_properties(entry_x64.asm PROPERTIES LINKER_FLAGS "/SAFESEH:NO")