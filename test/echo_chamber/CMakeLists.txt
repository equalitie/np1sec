include(FindPkgConfig)
################################################################################
set(CMAKE_BUILD_TYPE Debug)
set(GLOB BOOST_VERSION 1.58)

################################################################################
project (echo_chamber)
find_package(Boost ${BOOST_VERSION} COMPONENTS system thread unit_test_framework REQUIRED)
find_package(Threads)

add_definitions(-DBOOST_TEST_DYN_LINK)
add_definitions(-DBOOST_THREAD_VERSION=4)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread -ggdb ")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")

include_directories(
  "${Boost_INCLUDE_DIR}"
  "${CMAKE_SOURCE_DIR}/src")

file(GLOB sources "${CMAKE_SOURCE_DIR}/test/echo_chamber/*.cc")

add_executable(echo_chamber EXCLUDE_FROM_ALL ${sources})
target_link_libraries(echo_chamber ${Boost_LIBRARIES} np1sec)
