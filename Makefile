#
# Payment Request utility Makefile
#

# Add platform-dependent stuff to build_detect_platform
$(shell ./build_detect_platform build_config.mk)
include build_config.mk

CXXFLAGS = -g $(PLATFORM_CXXFLAGS)
LDFLAGS = $(PLATFORM_LDFLAGS)

PBFILES = paymentrequest.pb.h paymentrequest.pb.cc
TARGETS = paymentrequest-create paymentrequest-verify
LIBS = -lssl -lcrypto -lprotobuf

all: $(TARGETS) ca_in_a_box/certs/demomerchant.pem

# auto-generated dependencies:
-include *.P

$(PBFILES): paymentrequest.proto
	protoc --cpp_out=. $<

CREATEOBJS = obj/util.o obj/paymentrequest-create.o obj/paymentrequest.pb.o
paymentrequest-create: $(PBFILES) $(CREATEOBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(CREATEOBJS) $(LDFLAGS) $(LIBS)

VERIFYOBJS = obj/util.o obj/paymentrequest-verify.o obj/paymentrequest.pb.o
paymentrequest-verify: $(PBFILES) $(VERIFYOBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(VERIFYOBJS) $(LDFLAGS) $(LIBS)

ca_in_a_box/certs/demomerchant.pem:
	pushd ca_in_a_box && ./create_ca.sh && popd

clean:
	rm -f $(TARGETS)
	rm -f obj/*
	rm -f $(PBFILES)

# auto-generate dependencies:
obj/%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) -MMD -o $@ $<
	@cp $(@:%.o=%.d) $(@:%.o=%.P); \
	  sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
	      -e '/^$$/ d' -e 's/$$/ :/' < $(@:%.o=%.d) >> $(@:%.o=%.P); \
	  rm -f $(@:%.o=%.d)
obj/%.o: %.cc
	$(CXX) -c $(CXXFLAGS) -MMD -o $@ $<
	@cp $(@:%.o=%.d) $(@:%.o=%.P); \
	  sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
	      -e '/^$$/ d' -e 's/$$/ :/' < $(@:%.o=%.d) >> $(@:%.o=%.P); \
	  rm -f $(@:%.o=%.d)
