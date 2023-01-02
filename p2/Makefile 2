# Build a client and server using the student's files

# The executables will have the suffix .exe
EXESUFFIX = exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = requests crypto err file net my_crypto client

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = my_storage concurrenthashmap_factories 
SERVER_COMMON   = my_pool 
SERVER_PROVIDED = my_crypto crypto err file net server responses parsing

# Names for building the benchmark executable
BENCH_MAIN   = bench
BENCH_CXX    = bench

# NB: This Makefile does not add extra CXXFLAGS

container: 
	docker run --privileged --rm -v /Users/satyampatel/Desktop/CSE303/cse303_f22_sbp223/p2:/root --name cse303dev -it cse303

# Pull in the common build rules
include common.mk