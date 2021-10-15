cmake_minimum_required(VERSION 3.16.0 FATAL_ERROR)

project(tor_tools C CXX)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}) 

################################################################################
# Use solution folders feature
################################################################################
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
################################################################################
# Source groups
################################################################################
set(Header_Files__mini
    "mini/algorithm.h"
    "mini/allocator.h"
    "mini/buffer_ref.h"
    "mini/byte_buffer.h"
    "mini/byte_buffer_ref.h"
    "mini/common.h"
    "mini/compare.h"
    "mini/console.h"
    "mini/ctl.h"
    "mini/flags.h"
    "mini/function.h"
    "mini/hash.h"
    "mini/logger.h"
    "mini/memory.h"
    "mini/pair.h"
    "mini/ptr.h"
    "mini/stack_buffer.h"
    "mini/string.h"
    "mini/string_hash.h"
    "mini/string_ref.h"
    "mini/time.h"
)
source_group("Header Files//mini" FILES ${Header_Files__mini})

set(Header_Files__mini__collections
    "mini/collections/hashmap.h"
    "mini/collections/hashset.h"
    "mini/collections/linked_list.h"
    "mini/collections/list.h"
    "mini/collections/pair_list.h"
)
source_group("Header Files//mini//collections" FILES ${Header_Files__mini__collections})

set(Header_Files__mini__crt
    "mini/crt/crt0.h"
)
source_group("Header Files//mini//crt" FILES ${Header_Files__mini__crt})

set(Header_Files__mini__crypto
    "mini/crypto/aes.h"
    "mini/crypto/base16.h"
    "mini/crypto/base32.h"
    "mini/crypto/base64.h"
    "mini/crypto/common.h"
    "mini/crypto/curve25519.h"
    "mini/crypto/dh.h"
    "mini/crypto/hmac_sha256.h"
    "mini/crypto/random.h"
    "mini/crypto/rfc5869.h"
    "mini/crypto/rsa.h"
    "mini/crypto/sha1.h"
)
source_group("Header Files//mini//crypto" FILES ${Header_Files__mini__crypto})

set(Header_Files__mini__crypto__base
    "mini/crypto/base/key.h"
)
source_group("Header Files//mini//crypto//base" FILES ${Header_Files__mini__crypto__base})

set(Header_Files__mini__crypto__capi
    "mini/crypto/capi/aes.h"
    "mini/crypto/capi/base16.h"
    "mini/crypto/capi/base64.h"
    "mini/crypto/capi/dh.h"
    "mini/crypto/capi/hash.h"
    "mini/crypto/capi/hmac.h"
    "mini/crypto/capi/key.h"
    "mini/crypto/capi/provider.h"
    "mini/crypto/capi/random.h"
    "mini/crypto/capi/rsa.h"
)
source_group("Header Files//mini//crypto//capi" FILES ${Header_Files__mini__crypto__capi})

set(Header_Files__mini__crypto__capi__detail
    "mini/crypto/capi/detail/base_encode.h"
)
source_group("Header Files//mini//crypto//capi//detail" FILES ${Header_Files__mini__crypto__capi__detail})

set(Header_Files__mini__crypto__cng
    "mini/crypto/cng/aes.h"
    "mini/crypto/cng/curve25519.h"
    "mini/crypto/cng/dh.h"
    "mini/crypto/cng/hash.h"
    "mini/crypto/cng/hmac.h"
    "mini/crypto/cng/key.h"
    "mini/crypto/cng/provider.h"
    "mini/crypto/cng/random.h"
    "mini/crypto/cng/rsa.h"
)
source_group("Header Files//mini//crypto//cng" FILES ${Header_Files__mini__crypto__cng})

set(Header_Files__mini__crypto__ext
    "mini/crypto/ext/base32.h"
    "mini/crypto/ext/curve25519.h"
    "mini/crypto/ext/key.h"
)
source_group("Header Files//mini//crypto//ext" FILES ${Header_Files__mini__crypto__ext})

set(Header_Files__mini__crypto__ext__detail
    "mini/crypto/ext/detail/curve25519-donna.h"
)
source_group("Header Files//mini//crypto//ext//detail" FILES ${Header_Files__mini__crypto__ext__detail})

set(Header_Files__mini__ctl
    "mini/ctl/cctype.h"
    "mini/ctl/cstdlib.h"
    "mini/ctl/cstring.h"
)
source_group("Header Files//mini//ctl" FILES ${Header_Files__mini__ctl})

set(Header_Files__mini__io
    "mini/io/file.h"
    "mini/io/file_attributes.h"
    "mini/io/file_enumerator.h"
    "mini/io/file_stream.h"
    "mini/io/memory_stream.h"
    "mini/io/path.h"
    "mini/io/stream.h"
    "mini/io/stream_reader.h"
    "mini/io/stream_wrapper.h"
)
source_group("Header Files//mini//io" FILES ${Header_Files__mini__io})

set(Header_Files__mini__net
    "mini/net/http.h"
    "mini/net/ip_address.h"
    "mini/net/ssl_socket.h"
    "mini/net/ssl_stream.h"
    "mini/net/tcp_socket.h"
    "mini/net/uri.h"
)
source_group("Header Files//mini//net" FILES ${Header_Files__mini__net})

set(Header_Files__mini__net__detail
    "mini/net/detail/ssl_context.h"
)
source_group("Header Files//mini//net//detail" FILES ${Header_Files__mini__net__detail})

set(Header_Files__mini__threading
    "mini/threading/common.h"
    "mini/threading/event.h"
    "mini/threading/locked_value.h"
    "mini/threading/mutex.h"
    "mini/threading/thread.h"
    "mini/threading/thread_function.h"
)
source_group("Header Files//mini//threading" FILES ${Header_Files__mini__threading})

set(Header_Files__mini__tor
    "mini/tor/cell.h"
    "mini/tor/circuit.h"
    "mini/tor/circuit_node.h"
    "mini/tor/circuit_node_crypto_state.h"
    "mini/tor/common.h"
    "mini/tor/consensus.h"
    "mini/tor/hidden_service.h"
    "mini/tor/onion_router.h"
    "mini/tor/relay_cell.h"
    "mini/tor/tor_socket.h"
    "mini/tor/tor_stream.h"
)
source_group("Header Files//mini//tor" FILES ${Header_Files__mini__tor})

set(Header_Files__mini__tor__crypto
    "mini/tor/crypto/hybrid_encryption.h"
    "mini/tor/crypto/key_agreement.h"
    "mini/tor/crypto/key_agreement_ntor.h"
    "mini/tor/crypto/key_agreement_tap.h"
)
source_group("Header Files//mini//tor//crypto" FILES ${Header_Files__mini__tor__crypto})

set(Header_Files__mini__tor__parsers
    "mini/tor/parsers/consensus_parser.h"
    "mini/tor/parsers/hidden_service_descriptor_parser.h"
    "mini/tor/parsers/introduction_point_parser.h"
    "mini/tor/parsers/onion_router_descriptor_parser.h"
)
source_group("Header Files//mini//tor//parsers" FILES ${Header_Files__mini__tor__parsers})

set(Header_Files__mini__win32
    "mini/win32/api_set.h"
    "mini/win32/pe.h"
)
source_group("Header Files//mini//win32" FILES ${Header_Files__mini__win32})

set(Header_Files__mini__win32__api_set
    "mini/win32/api_set/api_set_enumerator.h"
    "mini/win32/api_set/api_set_value_enumerator.h"
    "mini/win32/api_set/common.h"
)
source_group("Header Files//mini//win32//api_set" FILES ${Header_Files__mini__win32__api_set})

set(Header_Files__mini__win32__pe
    "mini/win32/pe/common.h"
    "mini/win32/pe/export_directory_enumerator.h"
    "mini/win32/pe/import_directory_enumerator.h"
    "mini/win32/pe/import_thunk_enumerator.h"
    "mini/win32/pe/relocation_directory_enumerator.h"
    "mini/win32/pe/relocation_fixup_enumerator.h"
    "mini/win32/pe/resource_directory_enumerator.h"
    "mini/win32/pe/section_enumerator.h"
    "mini/win32/pe/tls_directory_enumerator.h"
)
source_group("Header Files//mini//win32//pe" FILES ${Header_Files__mini__win32__pe})

set(Source_Files
    "main.cpp"
    #"test.cpp"
)
source_group("Source Files" FILES ${Source_Files})

set(Source_Files__mini
    "mini/buffer_ref.inl"
    "mini/common.cpp"
    "mini/console.cpp"
    "mini/logger.cpp"
    "mini/memory.cpp"
    "mini/ptr.inl"
    "mini/stack_buffer.inl"
    "mini/string.cpp"
    "mini/string_ref.inl"
    "mini/time.cpp"
)
source_group("Source Files//mini" FILES ${Source_Files__mini})

set(Source_Files__mini__collections
    "mini/collections/hashmap.inl"
    "mini/collections/hashset.inl"
    "mini/collections/list.inl"
    "mini/collections/pair_list.inl"
)
source_group("Source Files//mini//collections" FILES ${Source_Files__mini__collections})

set(Source_Files__mini__crt
    "mini/crt/crt0.cpp"
    "mini/crt/msvcrt.def"
)
source_group("Source Files//mini//crt" FILES ${Source_Files__mini__crt})

set(Source_Files__mini__crypto__capi
    "mini/crypto/capi/aes.inl"
    "mini/crypto/capi/base16.cpp"
    "mini/crypto/capi/base64.cpp"
    "mini/crypto/capi/dh.inl"
    "mini/crypto/capi/hash.inl"
    "mini/crypto/capi/hmac.inl"
    "mini/crypto/capi/provider.cpp"
    "mini/crypto/capi/random.cpp"
    "mini/crypto/capi/rsa.inl"
)
source_group("Source Files//mini//crypto//capi" FILES ${Source_Files__mini__crypto__capi})

set(Source_Files__mini__crypto__capi__detail
    "mini/crypto/capi/detail/base_encode.cpp"
)
source_group("Source Files//mini//crypto//capi//detail" FILES ${Source_Files__mini__crypto__capi__detail})

set(Source_Files__mini__crypto__cng
    "mini/crypto/cng/aes.inl"
    "mini/crypto/cng/curve25519.cpp"
    "mini/crypto/cng/dh.inl"
    "mini/crypto/cng/hash.inl"
    "mini/crypto/cng/hmac.inl"
    "mini/crypto/cng/provider.cpp"
    "mini/crypto/cng/random.cpp"
    "mini/crypto/cng/rsa.inl"
)
source_group("Source Files//mini//crypto//cng" FILES ${Source_Files__mini__crypto__cng})

set(Source_Files__mini__crypto__ext
    "mini/crypto/ext/base32.cpp"
    "mini/crypto/ext/curve25519.cpp"
)
source_group("Source Files//mini//crypto//ext" FILES ${Source_Files__mini__crypto__ext})

set(Source_Files__mini__crypto__ext__detail
    "mini/crypto/ext/detail/curve25519-donna.cpp"
)
source_group("Source Files//mini//crypto//ext//detail" FILES ${Source_Files__mini__crypto__ext__detail})

set(Source_Files__mini__io
    "mini/io/file.cpp"
    "mini/io/file_attributes.cpp"
    "mini/io/file_enumerator.cpp"
    "mini/io/path.cpp"
)
source_group("Source Files//mini//io" FILES ${Source_Files__mini__io})

set(Source_Files__mini__net
    "mini/net/http.cpp"
    "mini/net/ssl_socket.cpp"
    "mini/net/ssl_stream.cpp"
    "mini/net/tcp_socket.cpp"
)
source_group("Source Files//mini//net" FILES ${Source_Files__mini__net})

set(Source_Files__mini__net__detail
    "mini/net/detail/ssl_context.cpp"
)
source_group("Source Files//mini//net//detail" FILES ${Source_Files__mini__net__detail})

set(Source_Files__mini__threading
    "mini/threading/event.cpp"
    "mini/threading/locked_value.inl"
    "mini/threading/mutex.cpp"
    "mini/threading/thread.cpp"
)
source_group("Source Files//mini//threading" FILES ${Source_Files__mini__threading})

set(Source_Files__mini__tor
    "mini/tor/cell.cpp"
    "mini/tor/circuit.cpp"
    "mini/tor/circuit_node.cpp"
    "mini/tor/circuit_node_crypto_state.cpp"
    "mini/tor/consensus.cpp"
    "mini/tor/hidden_service.cpp"
    "mini/tor/onion_router.cpp"
    "mini/tor/relay_cell.cpp"
    "mini/tor/tor_socket.cpp"
    "mini/tor/tor_stream.cpp"
)
source_group("Source Files//mini//tor" FILES ${Source_Files__mini__tor})

set(Source_Files__mini__tor__crypto
    "mini/tor/crypto/hybrid_encryption.cpp"
    "mini/tor/crypto/key_agreement_ntor.cpp"
    "mini/tor/crypto/key_agreement_tap.cpp"
)
source_group("Source Files//mini//tor//crypto" FILES ${Source_Files__mini__tor__crypto})

set(Source_Files__mini__tor__parsers
    "mini/tor/parsers/consensus_parser.cpp"
    "mini/tor/parsers/hidden_service_descriptor_parser.cpp"
    "mini/tor/parsers/introduction_point_parser.cpp"
    "mini/tor/parsers/onion_router_descriptor_parser.cpp"
)
source_group("Source Files//mini//tor//parsers" FILES ${Source_Files__mini__tor__parsers})

set(Source_Files__mini__win32__api_set
    "mini/win32/api_set/api_set_enumerator.cpp"
    "mini/win32/api_set/api_set_value_enumerator.cpp"
)
source_group("Source Files//mini//win32//api_set" FILES ${Source_Files__mini__win32__api_set})

set(Source_Files__mini__win32__pe
    "mini/win32/pe/export_directory_enumerator.cpp"
    "mini/win32/pe/import_directory_enumerator.cpp"
    "mini/win32/pe/import_thunk_enumerator.cpp"
    "mini/win32/pe/relocation_directory_enumerator.cpp"
    "mini/win32/pe/relocation_fixup_enumerator.cpp"
    "mini/win32/pe/resource_directory_enumerator.cpp"
    "mini/win32/pe/section_enumerator.cpp"
    "mini/win32/pe/tls_directory_enumerator.cpp"
)
source_group("Source Files//mini//win32//pe" FILES ${Source_Files__mini__win32__pe})

set(source_files_gumbo-parser
"gumbo-parser/attribute.c"
"gumbo-parser/char_ref.c"
"gumbo-parser/error.c"
"gumbo-parser/parser.c"
"gumbo-parser/string_buffer.c"
"gumbo-parser/string_piece.c"
"gumbo-parser/tag.c"
"gumbo-parser/tokenizer.c"
"gumbo-parser/utf8.c"
"gumbo-parser/util.c"
"gumbo-parser/vector.c"
"gumbo-parser/attribute.h"
"gumbo-parser/char_ref.h"
"gumbo-parser/error.h"
"gumbo-parser/gumbo.h"
"gumbo-parser/insertion_mode.h"
"gumbo-parser/parser.h"
"gumbo-parser/string_buffer.h"
"gumbo-parser/string_piece.h"
"gumbo-parser/strings.h"
"gumbo-parser/token_type.h"
"gumbo-parser/tokenizer.h"
"gumbo-parser/tokenizer_states.h"
"gumbo-parser/utf8.h"
"gumbo-parser/util.h"
"gumbo-parser/vector.h"
)
source_group("Source Files//gumbo-parser//" FILES ${source_files_gumbo-parser})

add_library(gumbo_lib STATIC ${source_files_gumbo-parser} )

#set_property(TARGET gumbo_lib PROPERTY
#  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(source_files_gumbo-query 
"gumbo-query/src/Document.cpp"
"gumbo-query/src/Node.cpp"
"gumbo-query/src/Object.cpp"
"gumbo-query/src/Parser.cpp"
"gumbo-query/src/QueryUtil.cpp"
"gumbo-query/src/Selection.cpp"
"gumbo-query/src/Selector.cpp"
"gumbo-query/src/Document.h"
"gumbo-query/src/Node.h"
"gumbo-query/src/Object.h"
"gumbo-query/src/Parser.h"
"gumbo-query/src/QueryUtil.h"
"gumbo-query/src/Selection.h"
"gumbo-query/src/Selector.h"
)

add_library(gumbo_query_lib STATIC ${source_files_gumbo-query} )
target_include_directories(gumbo_query_lib PUBLIC gumbo-parser)
#set_property(TARGET gumbo_query_lib PROPERTY
#  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")


set(ALL_FILES    
    ${Header_Files__mini}
    ${Header_Files__mini__collections}
    ${Header_Files__mini__crt}
    ${Header_Files__mini__crypto}
    ${Header_Files__mini__crypto__base}
    ${Header_Files__mini__crypto__capi}
    ${Header_Files__mini__crypto__capi__detail}
    ${Header_Files__mini__crypto__cng}
    ${Header_Files__mini__crypto__ext}
    ${Header_Files__mini__crypto__ext__detail}
    ${Header_Files__mini__ctl}
    ${Header_Files__mini__io}
    ${Header_Files__mini__net}
    ${Header_Files__mini__net__detail}
    ${Header_Files__mini__threading}
    ${Header_Files__mini__tor}
    ${Header_Files__mini__tor__crypto}
    ${Header_Files__mini__tor__parsers}
    ${Header_Files__mini__win32}
    ${Header_Files__mini__win32__api_set}
    ${Header_Files__mini__win32__pe}
    ${Source_Files}
    ${Source_Files__mini}
    ${Source_Files__mini__collections}
    ${Source_Files__mini__crt}
    ${Source_Files__mini__crypto__capi}
    ${Source_Files__mini__crypto__capi__detail}
    ${Source_Files__mini__crypto__cng}
    ${Source_Files__mini__crypto__ext}
    ${Source_Files__mini__crypto__ext__detail}
    ${Source_Files__mini__io}
    ${Source_Files__mini__net}
    ${Source_Files__mini__net__detail}
    ${Source_Files__mini__threading}
    ${Source_Files__mini__tor}
    ${Source_Files__mini__tor__crypto}
    ${Source_Files__mini__tor__parsers}
    ${Source_Files__mini__win32__api_set}
    ${Source_Files__mini__win32__pe}
)



################################################################################
# Target
################################################################################
add_executable(${PROJECT_NAME} ${ALL_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC gumbo-query/src)

################################################################################
# Includes for CMake from *.props
################################################################################



################################################################################
# Include directories
################################################################################
    target_include_directories(${PROJECT_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/."
    )


################################################################################
# Compile definitions
################################################################################

    target_compile_definitions(${PROJECT_NAME} PRIVATE
        "WIN32_LEAN_AND_MEAN;"
        "_WINSOCK_DEPRECATED_NO_WARNINGS;"
        "_CRT_SECURE_NO_WARNINGS;"
        "_SCL_SECURE_NO_WARNINGS;"
        "_CONSOLE"
    )


################################################################################
# Compile and link options
################################################################################

if(MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE            
            /MP;
            ${DEFAULT_CXX_DEBUG_INFORMATION_FORMAT};
            /wd4268;
            /wd4307;
            /wd4505;
            /std:c++latest;
            /Y-
        )

 

        target_link_options(${PROJECT_NAME} PRIVATE
            $<$<CONFIG:Debug>:
                /DEBUG;
                /INCREMENTAL
            >
 
            $<$<CONFIG:Release>:
                /NDEBUG;
                /OPT:REF;
                /OPT:ICF;
                /INCREMENTAL
            >
            /SUBSYSTEM:CONSOLE
        )

endif()

################################################################################
# Dependencies
################################################################################
    set(ADDITIONAL_LIBRARY_DEPENDENCIES
        "bcrypt;"
        "shlwapi;"
        "crypt32;"
        "wininet;"
        "ws2_32;"
        "secur32;"
        "ntdll;"
        "kernel32;"
        "user32;"
        "gdi32;"
        "winspool;"
        "comdlg32;"
        "advapi32;"
        "shell32;"
        "ole32;"
        "oleaut32;"
        "uuid;"
        "odbc32;"
        "odbccp32"
    )
#set_property(TARGET ${PROJECT_NAME} PROPERTY
#  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")


target_link_libraries(${PROJECT_NAME} PRIVATE "${ADDITIONAL_LIBRARY_DEPENDENCIES}" gumbo_lib gumbo_query_lib)

set_target_properties( ${PROJECT_NAME} PROPERTIES  VS_DEBUGGER_WORKING_DIRECTORY "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})
