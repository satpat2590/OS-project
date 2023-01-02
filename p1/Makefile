# Build a client and server using the student's files

# The executables will have the suffix .exe
EXESUFFIX = exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = client requests
CLIENT_COMMON   = crypto err file net my_crypto
CLIENT_PROVIDED = # This build does not use any pre-compiled solution files

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = server responses parsing my_storage \
                  sequentialmap_factories
SERVER_COMMON   = crypto err file net my_crypto
SERVER_PROVIDED = my_pool

# NB: This Makefile does not add extra CXXFLAGS


# running the docker container easily
container: 
	docker run --privileged --rm -v /Users/satyampatel/Desktop/CSE303/cse303_f22_sbp223/p2:/root --name cse303dev -it cse303

# Pull in the common build rules
include common.mk