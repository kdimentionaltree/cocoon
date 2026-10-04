if ((CMAKE_MAJOR_VERSION LESS 3) OR (CMAKE_VERSION VERSION_LESS "3.10"))
  message(FATAL_ERROR "CMake >= 3.10 is required")
endif()

option(TDCOCOON_ENABLE_INSTALL "Enable installation of the library." ON)

if (NOT DEFINED CMAKE_INSTALL_LIBDIR)
  set(CMAKE_INSTALL_LIBDIR "lib")
endif()


set(COCOON_SOURCE
        cocoon/AttestationCache.cpp
        cocoon/AttestationCache.h
        cocoon/CertManager.cpp
        cocoon/CertManager.h
        cocoon/FwdProxy.cpp
        cocoon/FwdProxy.h
        cocoon/RevProxy.cpp
        cocoon/RevProxy.h
        cocoon/pow.cpp
        cocoon/pow.h
        cocoon/utils.cpp
        cocoon/utils.h
        cocoon/ProxyConfig.cpp
        cocoon/ProxyConfig.h
        cocoon/RATLS.h
        cocoon/RATLS.cpp
        cocoon/Tee.h
        cocoon/Tee.cpp
        cocoon/tdx/tdx.cpp
        cocoon/tdx/tdx.h
        cocoon/tdx/PolicyConfig.cpp
        cocoon/tdx/PolicyConfig.h
        cocoon/tdx/RATLS.h
        cocoon/tdx/RATLS.cpp
        cocoon/tdx/Tee.h
        cocoon/tdx/Tee.cpp
        cocoon/sev/ABI.cpp
        cocoon/sev/ABI.h
        cocoon/sev/GuestCTX.cpp
        cocoon/sev/GuestCTX.h
        cocoon/sev/GuestDevice.cpp
        cocoon/sev/GuestDevice.h
        cocoon/sev/OVMF.cpp
        cocoon/sev/OVMF.h
        cocoon/sev/PKI.cpp
        cocoon/sev/PKI.h
        cocoon/sev/PolicyConfig.cpp
        cocoon/sev/PolicyConfig.h
        cocoon/sev/RATLS.cpp
        cocoon/sev/RATLS.h
        cocoon/sev/SEVHashes.cpp
        cocoon/sev/SEVHashes.h
        cocoon/sev/SHA384.h
        cocoon/sev/Tee.cpp
        cocoon/sev/Tee.h
        cocoon/sev/UUID.cpp
        cocoon/sev/UUID.h
        cocoon/sev/VMSA.cpp
        cocoon/sev/VMSA.h
)

set(COCOON_TEST_SOURCE
        ${CMAKE_CURRENT_SOURCE_DIR}/test/cocoon.cpp
)

find_path(SGX_DCAP_QVL_INCLUDE_DIR sgx_dcap_quoteverify.h)
find_library(SGX_DCAP_QVL_LIBRARY sgx_dcap_quoteverify)

find_path(TDX_ATTEST_INCLUDE_DIR tdx_attest.h)
find_library(TDX_ATTEST_LIBRARY tdx_attest)

find_path(SGX_DCAP_QL_INCLUDE_DIR sgx_dcap_ql_wrapper.h)
find_library(SGX_DCAP_QL_LIBRARY sgx_dcap_ql)

# Check if both attestation libraries are available
if(SGX_DCAP_QVL_INCLUDE_DIR AND SGX_DCAP_QVL_LIBRARY AND TDX_ATTEST_INCLUDE_DIR AND TDX_ATTEST_LIBRARY
    AND SGX_DCAP_QL_INCLUDE_DIR AND SGX_DCAP_QL_LIBRARY)
    set(ATTESTATION_AVAILABLE ON)
    message(STATUS "Found SGX DCAP and TDX attestation libraries - enabling attestation support")
    
    add_library(SGX::DCAPQuoteVerify SHARED IMPORTED)
    set_target_properties(SGX::DCAPQuoteVerify PROPERTIES
            IMPORTED_LOCATION ${SGX_DCAP_QVL_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${SGX_DCAP_QVL_INCLUDE_DIR}
    )
    
    add_library(TDX::Attest SHARED IMPORTED)
    set_target_properties(TDX::Attest PROPERTIES
            IMPORTED_LOCATION ${TDX_ATTEST_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${TDX_ATTEST_INCLUDE_DIR}
    )

    add_library(SGX::DCAPQuoteGenerate SHARED IMPORTED)
    set_target_properties(SGX::DCAPQuoteGenerate PROPERTIES
            IMPORTED_LOCATION ${SGX_DCAP_QL_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${SGX_DCAP_QL_INCLUDE_DIR}
    )

    set(ATTESTATION_LIBRARIES SGX::DCAPQuoteVerify TDX::Attest dcap_quoteprov)
else()
    set(ATTESTATION_AVAILABLE OFF)
    message(STATUS "SGX DCAP or TDX attestation libraries not found - disabling attestation support")
    set(ATTESTATION_LIBRARIES "")
endif()


add_library(cocoon STATIC ${COCOON_SOURCE})
target_link_libraries(cocoon PUBLIC tdutils PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${CMAKE_DL_LIBS} ${ZLIB_LIBRARIES} tdnet_ported ${ATTESTATION_LIBRARIES} cocoon_common)
target_include_directories(cocoon SYSTEM PRIVATE $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>)
target_include_directories(cocoon PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..)
target_include_directories(cocoon PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_include_directories(cocoon PUBLIC $<BUILD_INTERFACE:${TL_TD_AUTO_INCLUDE_DIR}>)

# Add compile definition based on attestation availability
if(ATTESTATION_AVAILABLE)
    target_compile_definitions(cocoon PUBLIC TD_TDX_ATTESTATION=1)
endif()

add_executable(test-cocoon EXCLUDE_FROM_ALL
  ${COCOON_TEST_SOURCE}
  ../ton/test/test-td-main.cpp)
target_link_libraries(test-cocoon PRIVATE cocoon tdactor tdnet_ported tonhttp)
target_include_directories(test-cocoon SYSTEM PRIVATE $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>)

add_executable(gen-cert EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/gen-cert.cpp)
target_link_libraries(gen-cert PRIVATE cocoon tdutils tdnet_ported tdactor)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_library(cocoon_wireguard_enrollment STATIC
    cocoon/WireGuardEnrollment.cpp
    cocoon/WireGuardIdentity.cpp)
  target_link_libraries(cocoon_wireguard_enrollment PRIVATE
    nlohmann_json::nlohmann_json ${OPENSSL_CRYPTO_LIBRARY} ${CMAKE_DL_LIBS})
  target_include_directories(cocoon_wireguard_enrollment PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cocoon)
  target_include_directories(cocoon_wireguard_enrollment SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})

  add_library(cocoon_wireguard_admission STATIC
    cocoon/WireGuardAdmission.cpp
    cocoon/WireGuardEvidence.cpp)
  target_link_libraries(cocoon_wireguard_admission PUBLIC cocoon_wireguard_enrollment PRIVATE
    cocoon tdactor tdnet_ported ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} nlohmann_json::nlohmann_json)
  target_include_directories(cocoon_wireguard_admission SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})
  if(ATTESTATION_AVAILABLE)
    target_include_directories(cocoon_wireguard_admission SYSTEM PRIVATE
      ${SGX_DCAP_QVL_INCLUDE_DIR} ${TDX_ATTEST_INCLUDE_DIR})
  endif()

  add_executable(cocoon-wireguard EXCLUDE_FROM_ALL cocoon/wireguard.cpp)
  target_link_libraries(cocoon-wireguard PRIVATE cocoon_wireguard_admission)
  target_include_directories(cocoon-wireguard SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})

  add_executable(test-wireguard EXCLUDE_FROM_ALL test/wireguard.cpp)
  target_link_libraries(test-wireguard PRIVATE
    cocoon_wireguard_enrollment nlohmann_json::nlohmann_json ${OPENSSL_CRYPTO_LIBRARY})
  target_include_directories(test-wireguard SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})

  add_executable(test-wireguard-admission EXCLUDE_FROM_ALL test/wireguard-admission.cpp)
  target_link_libraries(test-wireguard-admission PRIVATE
    cocoon_wireguard_admission cocoon tdactor tdnet_ported ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY}
    nlohmann_json::nlohmann_json)
  target_include_directories(test-wireguard-admission SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})
  if(ATTESTATION_AVAILABLE)
    target_include_directories(test-wireguard-admission SYSTEM PRIVATE ${SGX_DCAP_QVL_INCLUDE_DIR} ${TDX_ATTEST_INCLUDE_DIR})
  endif()
endif()

add_executable(router EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/router.cpp)
target_link_libraries(router PRIVATE cocoon tdutils tdnet_ported tdactor)

add_executable(tdx-info EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/tdx-info.cpp)
target_link_libraries(tdx-info PRIVATE cocoon tdutils tdnet_ported tdactor)

add_executable(sev-info EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/sev-info.cpp)
target_link_libraries(sev-info PRIVATE cocoon tdutils tdnet_ported tdactor)
target_include_directories(sev-info PUBLIC $<BUILD_INTERFACE:${TL_TD_AUTO_INCLUDE_DIR}>)

add_executable(cocoon-subst EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/cocoon-subst.cpp)
target_link_libraries(cocoon-subst PRIVATE tdutils)

add_executable(health-monitor EXCLUDE_FROM_ALL 
  ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/health-monitor.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/health-metrics.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/health-stats.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/health-render.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/tdx/eventlog.cpp
)
target_link_libraries(health-monitor PRIVATE cocoon tdutils tdnet_ported tdactor git)

add_executable(health-client EXCLUDE_FROM_ALL ${CMAKE_CURRENT_SOURCE_DIR}/cocoon/health-client.cpp)
target_link_libraries(health-client PRIVATE cocoon tdutils tdnet_ported tdactor)

# SGX enclave build (self-contained, returns early if SDK not found)
add_subdirectory(cocoon/tdx/sgx-enclave)
